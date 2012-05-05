#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "../sheep_priv.h"
#include "../strbuf.h"
#include "sheepfs.h"
#include "logger.h"
#include "net.h"

#define PATH_VDI	"/vdi"
#define PATH_VDI_LIST	"/vdi/list"
#define PATH_VDI_MOUNT	"/vdi/mount"
#define PATH_VDI_UNMOUNT  "/vdi/unmount"

int create_vdi_layout(void)
{
	if (shadow_dir_create(PATH_VDI) < 0)
		return -1;

	if (shadow_file_create(PATH_VDI_LIST) < 0)
		return -1;
	if (sheepfs_set_op(PATH_VDI_LIST, OP_VDI_LIST) < 0)
		return -1;

	if (shadow_file_create(PATH_VDI_MOUNT) < 0)
		return -1;
	if (sheepfs_set_op(PATH_VDI_MOUNT, OP_VDI_MOUNT) < 0)
		return -1;

	if (shadow_file_create(PATH_VDI_UNMOUNT) < 0)
		return -1;
	if (sheepfs_set_op(PATH_VDI_UNMOUNT, OP_VDI_UNMOUNT) < 0)
		return -1;

	return 0;
}

int vdi_list_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

size_t vdi_list_get_size(const char *path)
{
	struct strbuf *buf = sheepfs_run_cmd("collie vdi list");
	size_t len;

	if (!buf)
		return 0;

	len = shadow_file_fill(path, buf->buf, buf->len);
	strbuf_release(buf);
	return len;
}

int vdi_mount_write(const char *path, const char *buf, size_t size,
		    off_t ignore)
{
	if (volume_create_entry(buf) < 0)
		return -EIO;
	return size;
}

int vdi_unmount_write(const char *path, const char *buf, size_t size,
		      off_t ignore)
{
	if (volume_remove_entry(buf) < 0)
		return -EIO;
	return size;
}
