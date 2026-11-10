#define BUILDING_BASE_C
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/xnu_syscall/bsd/bsd_syscall_table.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>

// x86Sim (Align 1): a census of what the runtime asks for and gets refused: one line "<comm> <pid> <kind> <num>"
// per process and (kind, num) appended to /private/var/run/x86sim-unsupported.log (stdout of a launchd job goes
// nowhere, so the printf below was never seen). Cleared at boot by boot-a64.sh with the other run-state files.
void x86sim_unsupported(const char* kind, long num)
{
	static struct { const char* kind; long num; } seen[48];
	static int nseen;
	for (int k = 0; k < nseen; k++)
		if (seen[k].kind == kind && seen[k].num == num)
			return;
	if (nseen < 48)
	{
		seen[nseen].kind = kind;
		seen[nseen].num = num;
		nseen++;
	}
	char comm[20] = {0}, line[128];
	LINUX_SYSCALL(__NR_prctl, 16 /* PR_GET_NAME */, comm, 0UL, 0UL, 0UL);
	int n = __simple_snprintf(line, sizeof(line), "%s %d %s %ld\n", comm, (int)LINUX_SYSCALL0(__NR_getpid), kind, num);
	long fd = sys_openat(-2 /* AT_FDCWD */, "/private/var/run/x86sim-unsupported.log", 0x1 | 0x200 | 0x8 /* O_WRONLY|O_CREAT|O_APPEND */, 0644);
	if (fd < 0)
		return;
	sys_write(fd, line, n);
	sys_close(fd);
}

long __unknown_syscall(int nr, ...)
{
	__simple_printf("Unimplemented syscall (%d)\n", nr);
	x86sim_unsupported("syscall", nr);
	return -ENOSYS;
}

long __unknown_syscall_machdep(int nr, ...)
{
	__simple_printf("Unimplemented machdep trap (%d)\n", nr);
	x86sim_unsupported("machdep", nr);
	return -ENOSYS;
}

VISIBLE
int __linux_syscall(int nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	return linux_syscall(a1, a2, a3, a4, a5, a6, nr);
}

#ifdef __TESTING
void _start()
{
#ifdef __x86_64__
	__asm__ ("andq    $-16, %rsp");
#elif defined(__i386__
	__asm__ ("andl    $-16, %esp");
#endif
	__simple_printf("Hello world\n");
	LINUX_SYSCALL1(__NR_exit, 0);
}
#endif
