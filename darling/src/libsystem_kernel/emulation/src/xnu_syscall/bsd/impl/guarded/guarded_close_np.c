#include <darling/emulation/xnu_syscall/bsd/impl/guarded/guarded_close_np.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

long sys_guarded_close_np(int fd, uint64_t* guardid)
{
	// x86Code: the guard is the caller's input (const guardid_t* in XNU); it was overwritten with 0
	return sys_close(fd);
}
