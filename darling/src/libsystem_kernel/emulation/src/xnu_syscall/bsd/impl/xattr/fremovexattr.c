#include <sys/errno.h>
#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fremovexattr.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include "xattr_names.h"

long sys_fremovexattr(int fd, const char* name, int options)
{
	int ret;

	char lname[XATTR_LINUX_NAME_MAX];
	if (xattr_name_to_linux(name, lname) < 0)
		return -ENAMETOOLONG;
	ret = LINUX_SYSCALL(__NR_fremovexattr, fd, lname);

	if (ret < 0)
		return XATTR_ERR(ret);

	return ret;
}
