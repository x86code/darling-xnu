// This is needed so stat is not stat64
#define _DARWIN_NO_64_BIT_INODE

// NOTE: in this case, platform-include/sys/stat.h is used
#include <sys/stat.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getgid.h>

void stat_linux_to_bsd(const struct linux_stat* lstat, struct stat* stat)
{
	stat->st_dev = lstat->st_dev;
	stat->st_mode = lstat->st_mode;
	stat->st_nlink = lstat->st_nlink;
	stat->st_ino = lstat->st_ino;
	stat->st_uid = /*lstat->st_uid*/ sys_getuid();
	stat->st_gid = /*lstat->st_gid*/ sys_getgid();
	stat->st_rdev = lstat->st_rdev;
	stat->st_size = lstat->st_size;
	stat->st_blksize = lstat->st_blksize;
	stat->st_blocks = lstat->st_blocks;
	stat->st_atimespec.tv_sec = lstat->st_atime;
	stat->st_atimespec.tv_nsec = lstat->st_atime_nsec;
	stat->st_mtimespec.tv_sec = lstat->st_mtime;
	stat->st_mtimespec.tv_nsec = lstat->st_mtime_nsec;
	stat->st_ctimespec.tv_sec = lstat->st_ctime;
	stat->st_ctimespec.tv_nsec = lstat->st_ctime_nsec;
	stat->st_flags = 0;
}

void stat_linux_to_bsd64(const struct linux_stat* lstat, struct stat64* stat)
{
	stat->st_dev = lstat->st_dev;
	stat->st_mode = lstat->st_mode;
	stat->st_nlink = lstat->st_nlink;
	stat->st_ino = lstat->st_ino;
	stat->st_uid = /*lstat->st_uid*/ sys_getuid();
	stat->st_gid = /*lstat->st_gid*/ sys_getgid();
	stat->st_rdev = lstat->st_rdev;
	stat->st_size = lstat->st_size;
	stat->st_blksize = lstat->st_blksize;
	stat->st_blocks = lstat->st_blocks;
	stat->st_atimespec.tv_sec = lstat->st_atime;
	stat->st_atimespec.tv_nsec = lstat->st_atime_nsec;
	stat->st_mtimespec.tv_sec = lstat->st_mtime;
	stat->st_mtimespec.tv_nsec = lstat->st_mtime_nsec;
	stat->st_ctimespec.tv_sec = lstat->st_ctime;
	stat->st_ctimespec.tv_nsec = lstat->st_ctime_nsec;
	// x86Sim: was left uninitialized (stack garbage in getattrlist's ATTR_CMN_CRTIME/ADDEDTIME); Linux
	// stat has no birth time, so use the earlier of mtime and ctime
	if (lstat->st_mtime < lstat->st_ctime || (lstat->st_mtime == lstat->st_ctime && lstat->st_mtime_nsec < lstat->st_ctime_nsec))
		stat->st_birthtimespec = stat->st_mtimespec;
	else
		stat->st_birthtimespec = stat->st_ctimespec;
	stat->st_flags = 0;
}

// x86Sim: Linux ST_* mount flags to BSD MNT_* (they were copied unconverted: Linux's ST_VALID read as MNT_UNION,
// ST_RELATIME as MNT_LOCAL, and MNT_LOCAL was missing elsewhere; dirhelper (confstr/_dirhelper_relative) refuses
// non-local volumes with ENODEV, so chronod could not create its widget archive directories)
static unsigned int statfs_flags_linux_to_bsd(unsigned long lflags, long ftype)
{
	unsigned int f = 0;
	if (lflags & 0x0001) f |= 0x00000001; // ST_RDONLY -> MNT_RDONLY
	if (lflags & 0x0002) f |= 0x00000008; // ST_NOSUID -> MNT_NOSUID
	if (lflags & 0x0004) f |= 0x00000010; // ST_NODEV -> MNT_NODEV
	if (lflags & 0x0008) f |= 0x00000004; // ST_NOEXEC -> MNT_NOEXEC
	if (lflags & 0x0010) f |= 0x00000002; // ST_SYNCHRONOUS -> MNT_SYNCHRONOUS
	if (lflags & 0x0400) f |= 0x10000000; // ST_NOATIME -> MNT_NOATIME
	// local unless NFS (0x6969), SMB/CIFS (0x517b, 0xff534d42, 0xfe534d42) or FUSE (0x65735546)
	if (ftype != 0x6969 && ftype != 0x517b && ftype != (long)0xff534d42 && ftype != (long)0xfe534d42 && ftype != 0x65735546)
		f |= 0x00001000; // MNT_LOCAL
	f |= 0x00008000; // MNT_DOVOLFS (volfs-style lookups; getattrlist reports PATH_FROM_ID)
	return f;
}

void statfs_linux_to_bsd(const struct linux_statfs64* lstat, struct bsd_statfs* stat)
{
	stat->f_type = lstat->f_type;
	stat->f_bsize = lstat->f_bsize;
	stat->f_blocks = lstat->f_blocks;
	stat->f_bfree = lstat->f_bfree;
	stat->f_bavail = lstat->f_bavail;
	stat->f_files = lstat->f_files;
	stat->f_ffree = lstat->f_ffree;
	stat->f_fsid = lstat->f_fsid;
	stat->f_flags = statfs_flags_linux_to_bsd(lstat->f_flags, lstat->f_type);
}

void statfs_linux_to_bsd64(const struct linux_statfs64* lstat, struct bsd_statfs64* stat)
{
	stat->f_type = lstat->f_type;
	stat->f_bsize = lstat->f_bsize;
	stat->f_iosize = lstat->f_bsize;
	stat->f_blocks = lstat->f_blocks;
	stat->f_bfree = lstat->f_bfree;
	stat->f_bavail = lstat->f_bavail;
	stat->f_files = lstat->f_files;
	stat->f_ffree = lstat->f_ffree;
	stat->f_fsid = lstat->f_fsid;
	stat->f_flags = statfs_flags_linux_to_bsd(lstat->f_flags, lstat->f_type);
}

// x86Sim: see common.h
void stat_set_flags64(struct stat64* stat, unsigned int flags)
{
	stat->st_flags = flags;
}
