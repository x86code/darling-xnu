#include <darling/emulation/xnu_syscall/bsd/impl/process/setpriority.h>

void x86sim_jetsam_darwin_bg(int pid, int prio); // x86Sim RAM 2: process/memorystatus.c (jetsam.py)
void x86sim_jetsam_darwin_role(int pid, int role);

int sys_setpriority(int which, int who, int prio) {
	// x86Sim: PRIO_DARWIN_THREAD (3) and PRIO_DARWIN_PROCESS (4) (with PRIO_DARWIN_BG, PRIO_DARWIN_NONUI, ...) are
	// Darwin's background policies, which Linux rejects with EINVAL (RunningBoard logged "Error 22 setting priority to
	// PRIO_DARWIN_BG" for every process it backgrounds). Accepted without effect.
	// RAM 2: a process's PRIO_DARWIN_BG state is recorded for jetsam.py (background apps).
	if (which == 4)
		x86sim_jetsam_darwin_bg(who, prio);
	if (which == 6 /* PRIO_DARWIN_ROLE */)
	{
		x86sim_jetsam_darwin_role(who, prio);
		return 0;  // (Linux rejected it with EINVAL)
	}
	if (which == 3 || which == 4)
		return 0;
	return LINUX_SYSCALL(__NR_setpriority, which, who, prio);

	// TODO: Errors
}
