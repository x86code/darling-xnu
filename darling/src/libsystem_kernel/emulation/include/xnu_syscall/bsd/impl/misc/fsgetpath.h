#ifndef LINUX_FSGETPATH_H
#define LINUX_FSGETPATH_H

long sys_fsgetpath(const char* buf, unsigned long size, void* fsid, unsigned long long objid);

// x86Sim: getattrlist remembers (fsid, file ID) -> path for the IDs it hands out, so fsgetpath can
// resolve them (Linux has no inode -> path lookup); volumes then advertise VOL_CAP_FMT_PATH_FROM_ID
void fsgetpath_remember(unsigned int dev, unsigned long long ino, const char* path);

// x86Sim: a rename moves the remembered path of the renamed object (and of everything under a renamed directory),
// as XNU's fsgetpath follows the object: prepare before the Linux rename (Linux dfd + path), done after it succeeded
struct fsgp_rename
{
	unsigned int dev;
	unsigned long long ino;
	int known, isdir;
	char oldpath[1024];
};
void fsgetpath_rename_prepare(int ldfd, const char* lpath, struct fsgp_rename* r);
void fsgetpath_rename_done(int ldfd, const char* lpath, const struct fsgp_rename* r);

// x86Sim: openbyid_np (479), see fsgetpath.c
long sys_openbyid_np(void* fsid, void* objid, int oflags);

#endif // LINUX_FSGETPATH_H
