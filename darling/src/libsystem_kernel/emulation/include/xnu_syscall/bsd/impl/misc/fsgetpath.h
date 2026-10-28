#ifndef LINUX_FSGETPATH_H
#define LINUX_FSGETPATH_H

long sys_fsgetpath(const char* buf, unsigned long size, void* fsid, unsigned long long objid);

// x86Code: getattrlist remembers (fsid, file ID) -> path for the IDs it hands out, so fsgetpath can
// resolve them (Linux has no inode -> path lookup); volumes then advertise VOL_CAP_FMT_PATH_FROM_ID
void fsgetpath_remember(unsigned int dev, unsigned long long ino, const char* path);

#endif // LINUX_FSGETPATH_H
