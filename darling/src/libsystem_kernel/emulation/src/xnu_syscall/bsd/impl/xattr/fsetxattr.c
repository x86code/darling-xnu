#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fsetxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include "xattr_names.h"

long sys_fsetxattr(int fd, const char* name, const void* value,
		unsigned long size, unsigned int pos, int options)
{
	int ret;

	if (pos != 0)
		return -ERANGE;

	char lname[XATTR_LINUX_NAME_MAX];
	if (xattr_name_to_linux(name, lname) < 0)
		return -ENAMETOOLONG;
	ret = LINUX_SYSCALL(__NR_fsetxattr, fd, lname, value, size);

	if (ret < 0)
		return XATTR_ERR(ret);

	return ret;
}
