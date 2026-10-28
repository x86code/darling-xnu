#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstatfs.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/statfs.h>

#include <stddef.h>
#include <sys/fcntl.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/readlink.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

extern char *strtok_r(char *str, const char *delim, char **saveptr);
extern __SIZE_TYPE__ strlcpy(char* dst, const char* src, __SIZE_TYPE__ size);
extern __SIZE_TYPE__ strlen(const char* str);
extern int strncmp(const char* s1, const char* s2, __SIZE_TYPE__ len);
extern int sprintf(char *str, const char *format, ...);

long sys_fstatfs(int fd, struct bsd_statfs* buf)
{
#ifdef __x86_64__
	return sys_fstatfs64(fd, (struct bsd_statfs64*) buf);
#else
#	warning Not implemented
	return 0;
#endif
}

long sys_fstatfs64(int fd, struct bsd_statfs64* buf)
{
	int ret;
	struct linux_statfs64 lbuf;
	struct linux_stat lst;
	char procpath[64];
	char path[4096];

#ifdef __NR_fstatfs64
	ret = LINUX_SYSCALL3(__NR_fstatfs64, fd, sizeof(lbuf), &lbuf);
#else
	ret = LINUX_SYSCALL2(__NR_fstatfs, fd, &lbuf);
#endif

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	statfs_linux_to_bsd64(&lbuf, buf);
	buf->f_iosize = 512;

	// x86Code: f_fsid = { st_dev, 0 } as in statfs (matches getattrlist's ATTR_CMN_FSID).
	if (LINUX_SYSCALL(__NR_fstat, fd, &lst) == 0)
		buf->f_fsid = (unsigned int) lst.st_dev;

	// x86Code: match the mount table against the Linux path of the fd (fdpath() returns the
	// prefix view, which never matched mounts outside the prefix), then report the mount
	// point in the prefix view (statfs_fill_mount_info).
	sprintf(procpath, "/proc/self/fd/%d", fd);
#ifdef __NR_readlink
	ret = LINUX_SYSCALL(__NR_readlink, procpath, path, sizeof(path) - 1);
#else
	ret = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, procpath, path, sizeof(path) - 1);
#endif
	if (ret < 0)
		path[0] = 0;
	else
		path[ret] = 0;

	if (path[0] == '/')
		statfs_fill_mount_info(path, buf);
	else
	{
		buf->f_mntonname[0] = 0;
		buf->f_fstypename[0] = 0;
		buf->f_mntfromname[0] = 0;
	}
	return 0;
}
