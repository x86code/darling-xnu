#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/pthread_canceled.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_create.h>

#include <darlingserver/rpc.h>

// x86Sim: set (never cleared) by sys_pthread_markcancel. Every cancellation point (read, open, close, ... see
// CANCELATION_POINT) asks whether the calling thread was canceled, and each answer was a darlingserver RPC (installd
// made ~7,600 a second after boot). A thread is only ever marked through __pthread_markcancel, which libpthread
// calls on threads of its own process (pthread_cancel, _pthread_markcancel_if_canceled), so while no thread of this
// process was marked the answer is XNU's "not canceled" (EINVAL) and needs no round trip.
int __darling_cancel_marked;

long sys_pthread_canceled(int action)
{
	if (action == 0 && !uses_threads())
		return -EINVAL;
	if (action == 0 && !__atomic_load_n(&__darling_cancel_marked, __ATOMIC_ACQUIRE))
		return -EINVAL;

	int ret = dserver_rpc_pthread_canceled(action);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
