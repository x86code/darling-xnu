// x86Sim: __mac_syscall (MAC policy calls: Sandbox, AMFI, ...). Darling has no MAC
// policies. Nothing is sandboxed, so sandbox_check() (Sandbox call 2) answers
// "allowed" like XNU does for an unsandboxed process; ENOSYS made daemons such as
// cfprefsd refuse clients. Other calls are logged once and fail with ENOSYS.
// sandbox_container_path_for_pid/_audit_token (call 4) fails with ENOTSUP for a
// process without a container, as observed in the iOS simulator on a Mac.
#define SANDBOX_CALL_CHECK 2
// sandbox_passthrough_access (call 12) is how cfprefsd checks a client may write a
// preferences directory; with no sandbox there is nothing to deny.
#define SANDBOX_CALL_CONTAINER_PATH 4
#define SANDBOX_CALL_PASSTHROUGH_ACCESS 12
#include <darling/emulation/common/simple.h>
#include <stdint.h>
#include <sys/errno.h>

extern int strcmp(const char* a, const char* b);
extern unsigned long strlen(const char* s);

long sys___mac_syscall(const char* policy, int call, void* arg)
{
	static struct { char policy[32]; int call; } seen[32];
	static int nseen;
	int i;

	if (policy != 0 && strcmp(policy, "Sandbox") == 0
			&& (call == SANDBOX_CALL_CHECK || call == SANDBOX_CALL_PASSTHROUGH_ACCESS))
		return 0;
	if (policy != 0 && strcmp(policy, "Sandbox") == 0 && call == SANDBOX_CALL_CONTAINER_PATH)
		return -ENOTSUP;

	for (i = 0; i < nseen; i++)
		if (seen[i].call == call && strcmp(seen[i].policy, policy) == 0)
			return -ENOSYS;
	if (nseen < 32 && policy != 0 && strlen(policy) < sizeof(seen[0].policy))
	{
		__simple_sprintf(seen[nseen].policy, "%s", policy);
		seen[nseen].call = call;
		nseen++;
	}
	__simple_printf("__mac_syscall(%s, %d)\n", policy ? policy : "(null)", call);
	return -ENOSYS;
}

// x86Sim: persona (494). There are no personas; a simulator process on a Mac gets
// ESRCH from every persona call (kpersona_get, kpersona_pidinfo, ...), not ENOSYS.
long sys_persona(uint32_t operation, uint32_t flags, void* info, void* id, void* idlen, char* path)
{
	return -ESRCH;
}

// x86Sim: workloops with scheduling attributes (priority, policy, CPU percent). Workloops
// are emulated in kevent_qos.c on demand, so creating one succeeds and the attributes are
// ignored. (ENOTSUP sends libdispatch to a fallback that drains the workloop on a plain
// worker thread lacking the workloop thread state, crashing backboardd.)
long sys_kqueue_workloop_ctl(unsigned long cmd, uint64_t options, void* addr, unsigned long sz)
{
	if (cmd == 0x01 /* KQ_WORKLOOP_CREATE */)
		return 0;
	if (cmd == 0x02 /* KQ_WORKLOOP_DESTROY */)
		return 0;
	return -EINVAL;
}

// x86Sim: memorystatus_control (440) is in process/memorystatus.c (RAM 2: band changes are recorded for jetsam.py).
