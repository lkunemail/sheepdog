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

#define PATH_CLUSTER		"/cluster"
#define PATH_CLUSTER_INFO	"/cluster/info"

int create_cluster_layout(void)
{
	if (shadow_dir_create(PATH_CLUSTER) < 0)
		return -1;

	if (shadow_file_create(PATH_CLUSTER_INFO) < 0)
		return -1;
	sheepfs_set_op(PATH_CLUSTER_INFO, OP_CLUSTER_INFO);

	return 0;
}

int cluster_info_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

size_t cluster_info_get_size(const char *path)
{
	struct strbuf *buf = sheepfs_run_cmd("collie cluster info");
	size_t len;

	if (!buf)
		return 0;

	len = shadow_file_fill(path, buf->buf, buf->len);
	strbuf_release(buf);
	return len;
}
