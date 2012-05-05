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

#define PATH_NODE	"/node"
#define PATH_NODE_INFO	"/node/info"
#define PATH_NODE_LIST	"/node/list"


int create_node_layout(void)
{
	if (shadow_dir_create(PATH_NODE) < 0)
		return -1;

	if (shadow_file_create(PATH_NODE_INFO) < 0)
		return -1;
	sheepfs_set_op(PATH_NODE_INFO, OP_NODE_INFO);

	if (shadow_file_create(PATH_NODE_LIST) < 0)
		return -1;
	sheepfs_set_op(PATH_NODE_LIST, OP_NODE_LIST);

	return 0;
}

int node_info_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

size_t node_info_get_size(const char *path)
{
	struct strbuf *buf = sheepfs_run_cmd("collie node info");
	size_t len;

	if (!buf)
		return 0;

	len = shadow_file_fill(path, buf->buf, buf->len);
	strbuf_release(buf);
	return len;
}

int node_list_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

size_t node_list_get_size(const char *path)
{
	struct strbuf *buf = sheepfs_run_cmd("collie node list");
	size_t len;

	if (!buf)
		return 0;

	len = shadow_file_fill(path, buf->buf, buf->len);
	strbuf_release(buf);
	return len;
}
