#include <sys/errno.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

extern char *strcpy(char *dest, const char *src);
extern int do_linux_fchmodat(int fd, const char* path, int mode, int flag);

#define ATTR_BIT_MAP_COUNT 5

#define ATTR_CMN_CRTIME 0x200
#define ATTR_CMN_MODTIME 0x400
#define ATTR_CMN_CHGTIME 0x800
#define ATTR_CMN_ACCTIME 0x1000
#define ATTR_CMN_BKUPTIME 0x2000
#define ATTR_CMN_FNDRINFO 0x4000
#define ATTR_CMN_OWNERID 0x8000
#define ATTR_CMN_GRPID 0x10000
#define ATTR_CMN_ACCESSMASK 0x20000
#define ATTR_CMN_FLAGS 0x40000
#define ATTR_CMN_DATA_PROTECT_FLAGS 0x40000000
#define ATTR_CMN_EXTENDED_SECURITY 0x400000
#define ATTR_CMN_UUID 0x800000
#define ATTR_CMN_GRPUUID 0x1000000

// x86Sim: accept (and ignore, Linux cannot set them) creation and change times, which the
// code below already skips over. Foundation sets NSURLCreationDateKey on the new file when
// atomically replacing one; EINVAL made e.g. every lsd database save fail.
// x86Sim: also the Finder info (stored as the com.apple.FinderInfo xattr, as HFS+/APFS expose it; FSNode's
// setFinderInfo: failed with EINVAL, so PosterBoard could not create its poster "scratch" directories and drew no
// wallpaper), and backup time, owner/group, BSD flags and data protection class (accepted, ignored)
// x86Sim: and the ACL and owner/group UUIDs (accepted, ignored: Linux files here have no ACLs). installd's
// -[MIFileManager _bulkSetPropertiesForPath:...removeACL:] sets an empty ACL on every staged file; EINVAL failed
// every app install (x86sim install).
#define COMMON_SUPPORTED (ATTR_CMN_EXTENDED_SECURITY|ATTR_CMN_UUID|ATTR_CMN_GRPUUID|ATTR_CMN_CRTIME|ATTR_CMN_MODTIME|ATTR_CMN_CHGTIME|ATTR_CMN_ACCTIME|ATTR_CMN_BKUPTIME|ATTR_CMN_FNDRINFO|ATTR_CMN_OWNERID|ATTR_CMN_GRPID|ATTR_CMN_ACCESSMASK|ATTR_CMN_FLAGS|ATTR_CMN_DATA_PROTECT_FLAGS)
#define VOLUME_SUPPORTED 0
#define DIR_SUPPORTED 0
#define FILE_SUPPORTED 0
#define FORK_SUPPORTED 0

#define FSOPT_NOFOLLOW 1

#define LINUX_UTIME_OMIT	((1l << 30) - 2l)

struct timespec
{
	long tv_sec;
	long tv_nsec;
};

long
FUNC_NAME(int fd,

#if HAS_PATH
const char* path,
#endif

struct xnu_attrlist* alist, void *attributeBuffer, __SIZE_TYPE__ bufferSize, unsigned long options)
{
	int rv;
	char* next;
	int linux_at_flag = 0;

	if (options & FSOPT_NOFOLLOW)
		linux_at_flag |= LINUX_AT_SYMLINK_NOFOLLOW;

	if (!alist)
		return -EFAULT;

#if HAS_PATH
	if (!path)
		return -EFAULT;

	struct vchroot_expand_args vc;
	vc.flags = (options & FSOPT_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	strcpy(vc.path, path);
	rv = vchroot_expand(&vc);
	
	if (rv < 0)
		return rv;
#endif

	if (alist->bitmapcount < ATTR_BIT_MAP_COUNT)
		return -EINVAL;

	if ((alist->commonattr & COMMON_SUPPORTED) != alist->commonattr)
		return -EINVAL;
	if ((alist->volattr & VOLUME_SUPPORTED) != alist->volattr)
		return -EINVAL;
	if ((alist->dirattr & DIR_SUPPORTED) != alist->dirattr)
		return -EINVAL;
	if ((alist->fileattr & FILE_SUPPORTED) != alist->fileattr)
		return -EINVAL;
	if ((alist->forkattr & FORK_SUPPORTED) != alist->forkattr)
		return -EINVAL;

	next = (char*) attributeBuffer;

	if (alist->commonattr & ATTR_CMN_CRTIME)
	{
		struct timespec* ts = (struct timespec*) next;
		next += sizeof(struct timespec);
	}
    if (alist->commonattr & ATTR_CMN_MODTIME)
	{
		struct timespec* ts = (struct timespec*) next;
		struct timespec times[2] = {
			{ LINUX_UTIME_OMIT, LINUX_UTIME_OMIT },
			*ts
		};
#if HAS_PATH
		rv = LINUX_SYSCALL(__NR_utimensat, LINUX_AT_FDCWD, vc.path, times, linux_at_flag);
#else
		rv = LINUX_SYSCALL(__NR_utimensat, fd, 0, times, linux_at_flag);
#endif
		if (rv < 0)
			return errno_linux_to_bsd(rv);
		next += sizeof(struct timespec);
	}
	if (alist->commonattr & ATTR_CMN_CHGTIME)
	{
		struct timespec* ts = (struct timespec*) next;
		next += sizeof(struct timespec);
	}
	if (alist->commonattr & ATTR_CMN_ACCTIME)
	{
		struct timespec* ts = (struct timespec*) next;
		struct timespec times[2] = {
			*ts,
			{ LINUX_UTIME_OMIT, LINUX_UTIME_OMIT }
		};
#if HAS_PATH
		rv = LINUX_SYSCALL(__NR_utimensat, LINUX_AT_FDCWD, vc.path, times, linux_at_flag);
#else
		rv = LINUX_SYSCALL(__NR_utimensat, fd, 0, times, linux_at_flag);
#endif
		if (rv < 0)
			return errno_linux_to_bsd(rv);
		next += sizeof(struct timespec);
	}
	if (alist->commonattr & ATTR_CMN_BKUPTIME)
		next += sizeof(struct timespec);
	if (alist->commonattr & ATTR_CMN_FNDRINFO)
	{
		const char* fi = next;
		int zero = 1;
		for (int i = 0; i < 32; i++)
			if (fi[i])
				zero = 0;
		// all zeroes: no Finder info (remove the attribute; a missing one is fine)
#if HAS_PATH
		if (zero)
			rv = LINUX_SYSCALL((options & FSOPT_NOFOLLOW) ? __NR_lremovexattr : __NR_removexattr, vc.path, "user.com.apple.FinderInfo");
		else
			rv = LINUX_SYSCALL((options & FSOPT_NOFOLLOW) ? __NR_lsetxattr : __NR_setxattr, vc.path, "user.com.apple.FinderInfo", fi, 32, 0);
#else
		if (zero)
			rv = LINUX_SYSCALL(__NR_fremovexattr, fd, "user.com.apple.FinderInfo");
		else
			rv = LINUX_SYSCALL(__NR_fsetxattr, fd, "user.com.apple.FinderInfo", fi, 32, 0);
#endif
		if (rv < 0 && !(zero && rv == -61 /* LINUX_ENODATA */) && rv != -95 /* LINUX_EOPNOTSUPP: fs without xattrs */)
			return errno_linux_to_bsd(rv);
		next += 32;
	}
	if (alist->commonattr & ATTR_CMN_OWNERID)
		next += 4;
	if (alist->commonattr & ATTR_CMN_GRPID)
		next += 4;
    if (alist->commonattr & ATTR_CMN_ACCESSMASK)
	{
		int perms = *((int*) next);
#if HAS_PATH
		rv = do_linux_fchmodat(LINUX_AT_FDCWD, vc.path, perms, linux_at_flag);
#else
		rv = LINUX_SYSCALL(__NR_fchmod, fd, perms);
#endif
		if (rv < 0)
			return errno_linux_to_bsd(rv);
		next += 4;
	}
	// ATTR_CMN_FLAGS, ATTR_CMN_EXTENDED_SECURITY, ATTR_CMN_UUID, ATTR_CMN_GRPUUID, ATTR_CMN_DATA_PROTECT_FLAGS: ignored

	return 0;
}
