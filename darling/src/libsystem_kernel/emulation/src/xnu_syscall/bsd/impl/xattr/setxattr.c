#include <darling/emulation/xnu_syscall/bsd/impl/xattr/setxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include "xattr_names.h"


#define XATTR_NOFOLLOW	1

long sys_setxattr(const char* path, const char* name, const void* value,
		unsigned long size, unsigned int pos, int options)
{
	int ret;

	if (pos != 0)
		return -ERANGE;

	// x86Code: resolve the path in Darling's virtual root like getxattr/listxattr do
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
	if (options & XATTR_NOFOLLOW)
	{
		ret = LINUX_SYSCALL(__NR_lsetxattr, vc.path, lname, value, size);
	}
	else
	{
		ret = LINUX_SYSCALL(__NR_setxattr, vc.path, lname, value, size);
	}

	if (ret < 0)
		return XATTR_ERR(ret);

	return ret;
}
