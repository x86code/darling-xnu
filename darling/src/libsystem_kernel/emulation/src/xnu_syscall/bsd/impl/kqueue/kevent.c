#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent.h>
#include <darling/emulation/other/mach/foreign_hook.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

int __attribute__((weak)) __attribute__((visibility("default"))) kevent_impl(int kq, ...) { return -ENOSYS; }

long sys_kevent(int	kq, const struct kevent	*changelist, int nchanges,
			struct	kevent *eventlist, int nevents,
			const struct timespec *timeout)
{
	FOREIGN_HOOK(int (*)(int, const struct kevent*, int, struct kevent*, int, const struct timespec*),
		foreign, "__darling_sim_kevent_impl");
	int ret = foreign ? foreign(kq, changelist, nchanges, eventlist, nevents, timeout)
		: kevent_impl(kq, changelist, nchanges, eventlist, nevents, timeout);
	if (ret < 0)
		ret = -errno;
	return ret;
}
