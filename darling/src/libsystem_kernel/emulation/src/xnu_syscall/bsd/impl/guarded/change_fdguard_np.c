// x86Code: change_fdguard_np (BSD syscall 444). Network.framework guards every socket it owns
// (nw_fd_wrapper_guard); with ENOSYS it logged "Failed to guard socket fd" for each flow. Darling enforces no guards
// (guarded_close_np closes, guarded_open_np opens), so this only checks the descriptor and applies XNU's fdflags
// exchange: on input *fdflagsp holds the new descriptor flags (FD_CLOEXEC), on output the old ones.
#include <darling/emulation/xnu_syscall/bsd/impl/guarded/change_fdguard_np.h>

#include <stddef.h>
#include <sys/errno.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define LINUX_F_GETFD 1
#define LINUX_F_SETFD 2

long sys_change_fdguard_np(int fd, const uint64_t* guard, unsigned guardflags, const uint64_t* nguard,
		unsigned nguardflags, int* fdflagsp)
{
	int old = LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_GETFD, 0);
	if (old < 0)
		return errno_linux_to_bsd(old);
	if (fdflagsp != NULL) {
		int ret = LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETFD, *fdflagsp & 1 /* FD_CLOEXEC */);
		if (ret < 0)
			return errno_linux_to_bsd(ret);
		*fdflagsp = old;
	}
	return 0;
}
