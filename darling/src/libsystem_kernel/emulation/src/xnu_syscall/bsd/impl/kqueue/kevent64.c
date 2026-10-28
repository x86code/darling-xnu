#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent64.h>
#include <darling/emulation/other/mach/foreign_hook.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

int __attribute__((weak)) __attribute__((visibility("default"))) kevent64_impl(int kq, ...) { return -ENOSYS; }

long sys_kevent64(int kq, const struct kevent64_s *changelist, int nchanges,
			struct kevent64_s *eventlist, int nevents, unsigned int flags,
			const struct timespec *timeout)
{
	FOREIGN_HOOK(int (*)(int, const struct kevent64_s*, int, struct kevent64_s*, int, unsigned int, const struct timespec*),
		foreign, "__darling_sim_kevent64_impl");
	int ret = foreign ? foreign(kq, changelist, nchanges, eventlist, nevents, flags, timeout)
		: kevent64_impl(kq, changelist, nchanges, eventlist, nevents, flags, timeout);
	if (ret < 0)
		ret = -errno;
	return ret;
}
