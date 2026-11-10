#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getxattr.h>

#include <sys/errno.h>

extern char* strcpy(char* dst, const char* src);

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/xattr/getxattr.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include "xattr_names.h"

long sys_getxattr(const char* path, const char* name, char* value,
		unsigned long size, unsigned int pos, int options)
{
	int ret;

	if (pos != 0)
		return -ERANGE;

	struct vchroot_expand_args vc;
	vc.flags = (options & XATTR_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = get_perthread_wd();

	strcpy(vc.path, path);
	ret = vchroot_expand(&vc);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	char lname[XATTR_LINUX_NAME_MAX];
	if (xattr_name_to_linux(name, lname) < 0)
		return -ENAMETOOLONG;
	// x86Sim: XATTR_NOFOLLOW reads the link's own attributes (as removexattr/listxattr do).
	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_lgetxattr, vc.path, lname, value, size);
	else
		ret = LINUX_SYSCALL(__NR_getxattr, vc.path, lname, value, size);

	if (ret < 0)
		return XATTR_ERR(ret);

	// x86Sim: return the attribute's length (was 0), like fgetxattr; callers size their
	// buffer with getxattr(..., NULL, 0) and treated every attribute as empty.
	return ret;
}
