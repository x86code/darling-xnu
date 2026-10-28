#ifndef LINUX_STATFS_H
#define LINUX_STATFS_H

#include <darling/emulation/conversion/stat/common.h>

long sys_statfs(const char* path, struct bsd_statfs* buf);
long sys_statfs64(const char* path, struct bsd_statfs64* buf);

// x86Code: mount lookup shared by statfs, fstatfs and getfsstat (see statfs.c)
void statfs_fill_mount_info(const char* linux_path, struct bsd_statfs64* buf);
void statfs_unescape_mount_path(char* s);
void statfs_short_mntfrom(char* name, __SIZE_TYPE__ size); // x86Code
void statfs_mac_fstypename(char* name, __SIZE_TYPE__ size); // x86Code
void statfs_mount_path_to_darling(const char* linux_path, char* out, unsigned long outsize);

#endif // LINUX_STATFS_H
