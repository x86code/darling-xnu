#include <darling/emulation/xnu_syscall/bsd/impl/psynch/ulock_wait.h>

#include <sys/errno.h>
#include <stdbool.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/sigsafe_lock.h> // x86Sim

struct timespec
{
	long tv_sec;
	long tv_nsec;
};

// x86Sim: (ported from willi/darling-xnu#6) XNU's ulock_wait() returns how many other threads still wait on the
// address; futex(FUTEX_WAIT) doesn't say, so the waiters are counted here, per address. Userspace relies on the count
// both ways: os_unfair_lock keeps its waiters bit while it isn't 0, and pthread_dependency_wait_np() (and libdispatch's
// thread events) crash on anything but 0 for their single waiter. The hashed buckets used before counted every
// waiter on a colliding address too: backboardd SIGILLed in pthread_dependency_wait_np ("__ulock_wait() failed",
// -ret = -1) under CoreMotion/CoreLocation at boot.
#define ULOCK_WAITERS_MAX 512

struct ulock_waiters
{
	void* addr;
	uint32_t count;
};

static libsimple_lock_t ulock_waiters_lock = LIBSIMPLE_LOCK_INITIALIZER;
static struct ulock_waiters ulock_waiters[ULOCK_WAITERS_MAX];
static unsigned int ulock_waiters_used;

// Counts a waiter on `addr`; false if the table is full, and then it isn't counted.
static bool ulock_waiter_add(void* addr)
{
	bool added = true;
	unsigned int i;
	unsigned long long mask = sigsafe_lock(&ulock_waiters_lock);

	for (i = 0; i < ulock_waiters_used && ulock_waiters[i].addr != addr; i++);
	if (i < ulock_waiters_used)
		ulock_waiters[i].count++;
	else if (ulock_waiters_used < ULOCK_WAITERS_MAX)
		ulock_waiters[ulock_waiters_used++] = (struct ulock_waiters) { addr, 1 };
	else
		added = false;
	sigsafe_unlock(&ulock_waiters_lock, mask);
	return added;
}

// Uncounts a waiter on `addr`; returns how many are left.
static uint32_t ulock_waiter_remove(void* addr)
{
	uint32_t left = 0;
	unsigned int i;
	unsigned long long mask = sigsafe_lock(&ulock_waiters_lock);

	for (i = 0; i < ulock_waiters_used && ulock_waiters[i].addr != addr; i++);
	if (i < ulock_waiters_used)
	{
		left = --ulock_waiters[i].count;
		if (left == 0)
			ulock_waiters[i] = ulock_waiters[--ulock_waiters_used];
	}
	sigsafe_unlock(&ulock_waiters_lock, mask);
	return left;
}

void ulock_atfork_child(void)
{
	// the parent's other threads, and so their waits, don't exist in the child
	libsimple_lock_init(&ulock_waiters_lock);
	ulock_waiters_used = 0;
}

static long ulock_wait_ns(uint32_t operation, void* addr, uint64_t value, uint64_t timeout_ns);

// timeout is in us
long sys_ulock_wait(uint32_t operation, void* addr, uint64_t value, uint32_t timeout)
{
	return ulock_wait_ns(operation, addr, value, (uint64_t) timeout * 1000);
}

// x86Sim: ulock_wait2 (BSD syscall 544): XNU's ulock_wait with a 64-bit timeout in nanoseconds (or, with
// ULF_DEADLINE, a mach_absolute_time deadline). It was missing (ENOSYS); libdispatch uses it for every timed wait
// (dispatch_group_wait/dispatch_semaphore_wait with a timeout, _dlock_wait) and crashes on an unexpected error:
// "_dlock_wait.cold" SIGILL in Safari's WBSHistoryServiceStore load.
long sys_ulock_wait2(uint32_t operation, void* addr, uint64_t value, uint64_t timeout, uint64_t value2)
{
	if (operation & XNU_ULF_DEADLINE)
	{
		struct timespec now;
		LINUX_SYSCALL(__NR_clock_gettime, 1 /* CLOCK_MONOTONIC: Darling's mach_absolute_time, 1 ns ticks */, &now);
		uint64_t n = (uint64_t) now.tv_sec * 1000000000ull + now.tv_nsec;
		if (timeout == 0)
			timeout = 0;
		else if (timeout <= n)
			timeout = 1; // already past: wait as short as possible, then time out
		else
			timeout -= n;
		operation &= ~XNU_ULF_DEADLINE;
	}
	return ulock_wait_ns(operation, addr, value, timeout);
}

static long ulock_wait_ns(uint32_t operation, void* addr, uint64_t value, uint64_t timeout)
{
	int ret, op;
	struct timespec ts;


	// char dbg[100];
	// __simple_sprintf(dbg, "ulock_wait on %p for %d ns", addr, timeout / 1000);
	// lkm_call(0x1028, dbg);

	if (timeout > 0)
	{
		ts.tv_sec = timeout / 1000000000ull;
		ts.tv_nsec = timeout % 1000000000ull;
	}

	op = operation & XNU_UL_OPCODE_MASK;
	if (op == XNU_UL_COMPARE_AND_WAIT || op == XNU_UL_UNFAIR_LOCK)
	{
		bool counted = ulock_waiter_add(addr);
		ret = LINUX_SYSCALL(__NR_futex, addr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
			value, (timeout != 0) ? & ts : NULL);
		uint32_t left = counted ? ulock_waiter_remove(addr) : 0;

		// as XNU does, a wait that ended (or found the value changed: EAGAIN) returns how many other threads still
		// wait. With the table full, say there are some: userspace then takes the slow path, always safe for a lock.
		if (ret == 0 || ret == -LINUX_EAGAIN)
			ret = counted ? (int) left : 1;
	}
	else
		return -EINVAL;

	// x86Sim: returned verbatim to ULF_NO_ERRNO callers, which switch on the exact -errno; the libsyscall stubs
	// pass it through for them (ported from VibeDarling/darling-xnu#15)
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
