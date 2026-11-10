#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchflags.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/bsdflags.h>

// x86Sim: the flags are kept in an extended attribute (helper/misc/bsdflags.h); this used to fail with ENOTSUP.
long sys_fchflags(int fd, int flags)
{
	char buf[32];
	long r = x86sim_bsdflags_set(x86sim_fd_path(fd, buf), (uint32_t) flags);
	return r < 0 ? errno_linux_to_bsd(r) : 0;
}
