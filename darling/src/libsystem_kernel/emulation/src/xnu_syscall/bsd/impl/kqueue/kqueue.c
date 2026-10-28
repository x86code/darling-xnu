#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kqueue.h>
#include <darling/emulation/other/mach/foreign_hook.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>

int __attribute__((weak)) __attribute__((visibility("default"))) kqueue_impl(void)
{
	__simple_printf("No kqueue implementation?!\n");
	return -ENOSYS;
}

long sys_kqueue(void)
{
	FOREIGN_HOOK(int (*)(void), foreign, "__darling_sim_kqueue_impl");
	int ret = foreign ? foreign() : kqueue_impl();
	if (ret < 0)
		ret = -errno;
	return ret;
}
