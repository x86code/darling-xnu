#ifndef LINUX_STATFS_H
#define LINUX_STATFS_H

#include <darling/emulation/conversion/stat/common.h>

long sys_statfs(const char* path, struct bsd_statfs* buf);
long sys_statfs64(const char* path, struct bsd_statfs64* buf);

// x86Sim: mount lookup shared by statfs, fstatfs and getfsstat (see statfs.c)
// dev: st_dev of linux_path (0 = unknown). When the matched mount point has another st_dev (an unmounted
// btrfs subvolume), f_mntonname is the subvolume root instead (statfs_subvol_root).
void statfs_fill_mount_info(const char* linux_path, unsigned long long dev, struct bsd_statfs64* buf);
int statfs_subvol_root(const char* linux_path, unsigned long long dev, char* out, unsigned long outsize);
// Subvolume roots getfsstat lists after /proc/self/mounts: index i (0-based) into out (Linux path).
int statfs_extra_root(int i, char* out, unsigned long outsize, unsigned long long* dev);
void statfs_unescape_mount_path(char* s);
void statfs_short_mntfrom(char* name, __SIZE_TYPE__ size); // x86Sim
void statfs_mac_fstypename(char* name, __SIZE_TYPE__ size); // x86Sim
void statfs_mount_path_to_darling(const char* linux_path, char* out, unsigned long outsize);

#endif // LINUX_STATFS_H
