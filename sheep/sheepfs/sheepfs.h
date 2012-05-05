#ifndef SHEEPFS_H
#define SHEEPFS_H

enum sheepfs_opcode {
	OP_NULL = 0,
	OP_CLUSTER_INFO,
	OP_VDI_LIST,
	OP_VDI_MOUNT,
};

extern char sheepfs_shadow[];

extern struct strbuf *sheepfs_run_cmd(const char *command);
extern int sheepfs_init(const char *dir);
extern int sheepfs_set_op(const char *path, unsigned opcode);

/* shadow_file.c */
extern size_t shadow_file_fill(const char *path, char *buf, size_t size);
extern int shadow_file_read(const char *, char *buf, size_t size, off_t);
extern int shadow_dir_create(const char *path);
extern int shadow_file_create(const char *path);
extern int shadow_file_setxattr(const char *path, const char *name,
				const void *value, size_t size);
extern int shadow_file_getxattr(const char *path, const char *name,
				void *value, size_t size);
extern int shadow_file_delete(const char *path);
extern int shadow_file_exsit(const char *path);

/* cluster.c */
extern int cluster_info_read(const char *path, char *buf, size_t size, off_t);
extern size_t cluster_info_get_size(const char *path);
extern int create_cluster_layout(void);

/* vdi.c */
extern int create_vdi_layout(void);
extern int vdi_list_read(const char *path, char *buf, size_t size, off_t);
extern size_t vdi_list_get_size(const char *path);

extern int vdi_mount_write(const char *, const char *buf, size_t size, off_t);

#endif
