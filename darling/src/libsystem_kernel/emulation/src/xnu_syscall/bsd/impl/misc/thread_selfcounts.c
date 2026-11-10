// x86Sim: SYS_thread_selfcounts (186). SpringBoard / libmalloc poll this in a tight
// loop; Darling left the slot empty so every call printed "Unimplemented syscall (186)"
// and returned -ENOSYS, burning a core and stalling UI presents. Type 1 writes
// {instructions, cycles}; we approximate both with CLOCK_MONOTONIC nanoseconds so
// successive samples are strictly monotonic (callers expect growth).
#include <darling/emulation/xnu_syscall/bsd/impl/misc/thread_selfcounts.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct linux_timespec {
	long tv_sec;
	long tv_nsec;
};

long sys_thread_selfcounts(int type, void* buf, unsigned long nbytes)
{
	uint64_t counts[2];
	struct linux_timespec ts;
	uint64_t t;
	unsigned long n;
	long rv;

	if (type != 1)
		return -EINVAL;
	if (!buf || nbytes == 0)
		return -EFAULT;

	/* CLOCK_MONOTONIC == 1; same stand-in ulock_wait uses for mach_absolute_time. */
	rv = LINUX_SYSCALL(__NR_clock_gettime, 1, &ts);
	if (rv < 0)
		return -EINVAL;

	t = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	counts[0] = t; /* instructions (monotonic stand-in) */
	counts[1] = t; /* cycles */

	n = nbytes < sizeof(counts) ? nbytes : sizeof(counts);
	memcpy(buf, counts, n);
	return 0;
}
