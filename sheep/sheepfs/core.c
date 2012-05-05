#include <fuse.h>
#include <errno.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <dirent.h>
#include <pthread.h>

#include "strbuf.h"
#include "logger.h"
#include "sheepfs.h"

#define SH_OP_NAME   "user.sheepfs.opcode"
#define SH_OP_SIZE   sizeof(uint32_t)

char sheepfs_shadow[PATH_MAX];

static struct sheepfs_file_operation {
	int (*read)(const char *path, char *buf, size_t size, off_t);
	int (*write)(const char *path, const char *buf, size_t size, off_t);
	size_t (*get_size)(const char *path);
} sheepfs_file_ops[] = {
	[OP_NULL]	  = { NULL, NULL, NULL },
	[OP_CLUSTER_INFO] = { cluster_info_read, NULL,
				cluster_info_get_size },
};

int sheepfs_set_op(const char *path, unsigned opcode)
{
	if (shadow_file_setxattr(path, SH_OP_NAME, &opcode, SH_OP_SIZE) < 0) {
		shadow_file_delete(path);
		return -1;
	}
	return 0;
}

static unsigned sheepfs_get_op(const char *path)
{
	unsigned opcode = 0;

	/* If fail, we simply return 0 to run NULL operation */
	shadow_file_getxattr(path, SH_OP_NAME, &opcode, SH_OP_SIZE);

	return opcode;
}

static size_t sheepfs_get_size(const char *path)
{
	unsigned op = sheepfs_get_op(path);

	if (sheepfs_file_ops[op].get_size)
		return sheepfs_file_ops[op].get_size(path);

	return 0;
}

static int sheepfs_getattr(const char *path, struct stat *st)
{
	struct strbuf p = STRBUF_INIT;
	int ret;

	strbuf_addf(&p, "%s%s", sheepfs_shadow, path);
	ret = stat(p.buf, st);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}
	if (S_ISREG(st->st_mode))
		st->st_size = sheepfs_get_size(path);
out:
	strbuf_release(&p);
	return ret;
}

static int sheepfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi)
{
	DIR *dir;
	struct dirent *dentry;
	struct strbuf p = STRBUF_INIT;
	int ret = 0;

	strbuf_addf(&p, "%s%s", sheepfs_shadow, path);
	dir = opendir(p.buf);
	if (!dir) {
		ret = -errno;
		dprintf("%m\n");
		goto out;
	}

	while ((dentry = readdir(dir))) {
		if (filler(buf, dentry->d_name, NULL, 0) != 0) {
			dprintf("out of memory\n");
			ret = -ENOMEM;
			goto out;
		}
	}

out:
	strbuf_release(&p);
	return ret;
}

static int sheepfs_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	int ret = 0;
	unsigned op = sheepfs_get_op(path);

	if (sheepfs_file_ops[op].read)
		ret = sheepfs_file_ops[op].read(path, buf, size, offset);

	return ret;
}

static int sheepfs_write(const char *path, const char *buf, size_t size,
			 off_t offset, struct fuse_file_info *fi)
{
	int ret = 0;
	unsigned op = sheepfs_get_op(path);

	if (sheepfs_file_ops[op].write)
		ret = sheepfs_file_ops[op].write(path, buf, size, offset);

	return ret;
}

static int sheepfs_truncate(const char *path, off_t size)
{
	struct strbuf p = STRBUF_INIT;
	int ret = 0, fd;

	strbuf_addf(&p, "%s%s", sheepfs_shadow, path);
	fd = open(p.buf, O_RDWR);
	if (fd < 0)
		ret = -ENOENT;
	else
		close(fd);

	strbuf_release(&p);
	return ret;
}

struct fuse_operations sheepfs_ops =  {
	.getattr  = sheepfs_getattr,
	.readdir  = sheepfs_readdir,
	.truncate = sheepfs_truncate,
	.read     = sheepfs_read,
	.write    = sheepfs_write,
};

static void sheepfs_main_loop(char *root)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	int ret = -1;

	dprintf("%s\n", root);
	if (mkdir(root, 0755) < 0) {
		if (errno != EEXIST) {
			eprintf("%m\n");
			return;
		}
	}

	fuse_opt_add_arg(&args, "sheepfs"); /* placeholder for argv[0] */
	fuse_opt_add_arg(&args, "-ofsname=sheepfs");
	fuse_opt_add_arg(&args, root);
	ret = fuse_main(args.argc, args.argv, &sheepfs_ops, NULL);
	dprintf("sheepfs daemon exited %d\n", ret);
	return;
}

static int create_sheepfs_layout(void)
{
	if (create_cluster_layout() < 0)
		return -1;

	return 0;
}

int sheepfs_init(const char *dir)
{
	struct strbuf path = STRBUF_INIT;
	pid_t pid;

	strbuf_addf(&path, "%s/%s", dir, ".sheepfs");
	memcpy(sheepfs_shadow, path.buf, path.len);
	if (mkdir(sheepfs_shadow, 0755) < 0) {
		if (errno != EEXIST) {
			eprintf("%m\n");
			return -1;
		}
	}

	create_sheepfs_layout();
	strbuf_reset(&path);
	strbuf_addf(&path, "%s/%s", dir, "sheepfs");

	pid = fork();
	if (pid < 0) {
		eprintf("failed to fork sheepfs daemon: %m");
		return -1;
	} else if (pid) {
		strbuf_release(&path);
		return 0;
	} else /* child */ {
		sheepfs_main_loop(path.buf);
		exit(0);
	}
}

struct strbuf *sheepfs_run_cmd(const char *command)
{
	struct strbuf *buf = xmalloc(sizeof(*buf));
	FILE *f = popen(command, "re");

	if (!f) {
		dprintf("popen failed\n");
		goto err;
	}

	strbuf_init(buf, 4096);

	while (!feof(f))
		strbuf_fread(buf, 4096, f);

	pclose(f);
	return buf;
err:
	strbuf_release(buf);
	pclose(f);
	free(buf);
	return NULL;
}
