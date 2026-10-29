#include <darling/emulation/xnu_syscall/bsd/impl/process/setpriority.h>

int sys_setpriority(int which, int who, int prio) {
	// x86Code: PRIO_DARWIN_THREAD (3) and PRIO_DARWIN_PROCESS (4) (with PRIO_DARWIN_BG, PRIO_DARWIN_NONUI, ...) are
	// Darwin's background policies, which Linux rejects with EINVAL (RunningBoard logged "Error 22 setting priority to
	// PRIO_DARWIN_BG" for every process it backgrounds). Accepted without effect.
	if (which == 3 || which == 4)
		return 0;
	return LINUX_SYSCALL(__NR_setpriority, which, who, prio);

	// TODO: Errors
}
