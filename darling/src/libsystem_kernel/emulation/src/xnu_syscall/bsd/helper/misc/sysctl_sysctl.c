#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_sysctl.h>

#include <mach/machine.h>
#include <sys/errno.h>

#include <darlingserver/rpc.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/base.h>

enum {
	_PROC_CPUTYPE = 1000,
};

static sysctl_handler(handle_proc_cputype);

const struct known_sysctl sysctls_sysctl[] = {
	{ .oid = _PROC_CPUTYPE, .type = CTLTYPE_INT, .exttype = "I", .name = "proc_cputype", .handler = handle_proc_cputype },
	{ .oid = -1 }
};

sysctl_handler(handle_proc_cputype)
{
	if (nlen < 3)
		return -ENOENT;

	bool is64bit;
	if (dserver_rpc_task_is_64_bit(name[2], &is64bit) < 0) {
		// x86Code: darlingserver's lookup by NSID misses some live processes (simulator apps started suspended
		// after a first debugging session in the container), which made debugserver pick i386 and crash in
		// MachThread::ThreadDidStop. A process that exists here runs under the 64-bit mldr on x86-64 hosts
		// (32-bit Darwin processes use mldr32, which Darling no longer builds by default).
		if (LINUX_SYSCALL(__NR_kill, name[2], 0) < 0)
			return -ENOENT;
#if defined(__x86_64__) || defined(__aarch64__)
		is64bit = true;
#else
		is64bit = false;
#endif
	}

	if (*oldlen < sizeof(int))
		return -EINVAL;

#if defined(__i386__) || defined(__x86_64__)
	*((unsigned int*) old) = CPU_TYPE_I386;
#elif defined(__arm__) || defined(__aarch64__)
	*((unsigned int*) old) = CPU_TYPE_ARM;
#else
#	warning Missing code for this arch!
	*((unsigned int*) old) = 0;
#endif

	if (is64bit)
		*((unsigned int*) old) |= CPU_ARCH_ABI64;


	return 0;
}
