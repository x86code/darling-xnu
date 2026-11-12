#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_hw.h>

#include <mach/host_info.h>
#include <mach/machine.h>
#include <mach/mach_init.h>
#include <sys/errno.h>

#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_kern.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_proc.h>
#include <darling/emulation/linux_premigration/ext/sys/utsname.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/string.h>

extern kern_return_t mach_port_deallocate(ipc_space_t task, mach_port_name_t name);
extern kern_return_t host_info(mach_port_name_t host, int itype, void* hinfo, mach_msg_type_number_t* count);

/* Darling specific */
enum {
	_HW_PHYSICAL_CPU = 1000,
	_HW_PHYSICAL_CPU_MAX,
	_HW_LOGICAL_CPU,
	_HW_LOGICAL_CPU_MAX,
	_HW_CPUTYPE,
	_HW_CPUSUBTYPE,
	_HW_CPUTHREADTYPE,
	_HW_64BITCAPABLE,
	_HW_CPUFREQUENCY = 15,
	_HW_CPUFAMILY = 1100, // x86Sim (Speed 27): the arm64 identity below
	_HW_CPUSUBFAMILY,
	_HW_OPTIONAL,
	_HW_OPTIONAL_ARM,
	_HW_ACTIVECPU = 1200, // x86Sim: activecpu, nperflevels, perflevel0.* (OID_AUTO in XNU)
	_HW_NPERFLEVELS,
	_HW_PERFLEVEL0,
};

/*
 * x86Sim (Speed 27): an arm64 iOS-simulator process (host/arm64host; darling_x86sim_arm64) runs on an emulated
 * Apple-silicon CPU, and a Mac's simulator processes see the Mac's: hw.cputype CPU_TYPE_ARM64, hw.machine "arm64"
 * (uname), hw.cpufamily, hw.optional.arm64 and the hw.optional.arm.FEAT_* keys. They saw the Linux host's x86_64:
 * Core ML compiled models "for platform intel" (E5), whose BNNS path an arm64 runtime doesn't have, and Spotlight's
 * query parser couldn't load its model in time (a nil token: Spotlight crashed on typing). The features are an M1's
 * (the Mac mini these runtimes are compared with, Macmini9,1) limited to what the JIT executes (dynarmic + the
 * fallback: LSE/LSE2, LRCPC, FP16, JSCVT, CRC32, AES/SHA1/SHA256/PMULL); the rest read 0, as on a CPU without them.
 * Other processes keep the host's identity and get no hw.optional (Darling never had it).
 */
#ifndef VARIANT_DYLD
extern bool darling_x86sim_arm64;
#define X86SIM_ARM64() (darling_x86sim_arm64)
#else
#define X86SIM_ARM64() 0
#endif
#define X86SIM_CPU_TYPE_ARM64 0x0100000c
#define X86SIM_CPU_SUBTYPE_ARM64E 2
#define X86SIM_CPUFAMILY_ARM_FIRESTORM_ICESTORM 0x1b588bb3

static sysctl_handler(handle_cpufamily);
static sysctl_handler(handle_cpusubfamily);
static sysctl_handler(handle_optional_one);
static sysctl_handler(handle_optional_zero);

// hw.optional.* (oids under _HW_OPTIONAL; an arm64 process only)
static const struct known_sysctl sysctls_hw_optional_arm[] = {
	{ .oid = 1, .type = CTLTYPE_INT, .exttype = "I", .name = "AdvSIMD", .handler = handle_optional_one },
	{ .oid = 2, .type = CTLTYPE_INT, .exttype = "I", .name = "AdvSIMD_HPFPCvt", .handler = handle_optional_one },
	{ .oid = 3, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_FP16", .handler = handle_optional_one },
	{ .oid = 4, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_CRC32", .handler = handle_optional_one },
	{ .oid = 5, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_LSE", .handler = handle_optional_one },
	{ .oid = 6, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_LSE2", .handler = handle_optional_one },
	{ .oid = 7, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_LRCPC", .handler = handle_optional_one },
	{ .oid = 8, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_JSCVT", .handler = handle_optional_one },
	{ .oid = 9, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_AES", .handler = handle_optional_one },
	{ .oid = 10, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_PMULL", .handler = handle_optional_one },
	{ .oid = 11, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_SHA1", .handler = handle_optional_one },
	{ .oid = 12, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_SHA256", .handler = handle_optional_one },
	{ .oid = 13, .type = CTLTYPE_INT, .exttype = "I", .name = "FP_SyncExceptions", .handler = handle_optional_zero },
	{ .oid = 14, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_DotProd", .handler = handle_optional_zero },
	{ .oid = 15, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_FHM", .handler = handle_optional_zero },
	{ .oid = 16, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_BF16", .handler = handle_optional_zero },
	{ .oid = 17, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_I8MM", .handler = handle_optional_zero },
	{ .oid = 18, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_SME", .handler = handle_optional_zero },
	{ .oid = 19, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_SME2", .handler = handle_optional_zero },
	{ .oid = 20, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_SHA3", .handler = handle_optional_zero },
	{ .oid = 21, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_SHA512", .handler = handle_optional_zero },
	{ .oid = 22, .type = CTLTYPE_INT, .exttype = "I", .name = "FEAT_RDM", .handler = handle_optional_zero },
	{ .oid = -1 }
};
static const struct known_sysctl sysctls_hw_optional[] = {
	{ .oid = 1, .type = CTLTYPE_INT, .exttype = "I", .name = "arm64", .handler = handle_optional_one },
	{ .oid = 2, .type = CTLTYPE_INT, .exttype = "I", .name = "floatingpoint", .handler = handle_optional_one },
	{ .oid = 3, .type = CTLTYPE_INT, .exttype = "I", .name = "neon", .handler = handle_optional_one },
	{ .oid = 4, .type = CTLTYPE_INT, .exttype = "I", .name = "neon_hpfp", .handler = handle_optional_one },
	{ .oid = 5, .type = CTLTYPE_INT, .exttype = "I", .name = "neon_fp16", .handler = handle_optional_one },
	{ .oid = 6, .type = CTLTYPE_INT, .exttype = "I", .name = "armv8_crc32", .handler = handle_optional_one },
	{ .oid = 7, .type = CTLTYPE_INT, .exttype = "I", .name = "armv8_1_atomics", .handler = handle_optional_one },
	{ .oid = 8, .type = CTLTYPE_INT, .exttype = "I", .name = "armv8_2_fhm", .handler = handle_optional_zero },
	{ .oid = 9, .type = CTLTYPE_INT, .exttype = "I", .name = "armv8_2_sha3", .handler = handle_optional_zero },
	{ .oid = 10, .type = CTLTYPE_INT, .exttype = "I", .name = "armv8_2_sha512", .handler = handle_optional_zero },
	{ .oid = 11, .type = CTLTYPE_INT, .exttype = "I", .name = "armv8_3_compnum", .handler = handle_optional_zero },
	{ .oid = 12, .type = CTLTYPE_INT, .exttype = "I", .name = "ucnormal_mem", .handler = handle_optional_one },
	{ .oid = 13, .type = CTLTYPE_INT, .exttype = "I", .name = "amx_version", .handler = handle_optional_zero },
	{ .oid = _HW_OPTIONAL_ARM, .type = CTLTYPE_NODE, .exttype = "", .name = "arm", .subctls = sysctls_hw_optional_arm },
	{ .oid = -1 }
};

static sysctl_handler(handle_availcpu);
static sysctl_handler(handle_cachelinesize);
static sysctl_handler(handle_l1icachesize);
static sysctl_handler(handle_l1dcachesize);
static sysctl_handler(handle_l2cachesize);
static sysctl_handler(handle_tbfrequency);
static sysctl_handler(handle_nperflevels);
static sysctl_handler(handle_perflevel_name);
static sysctl_handler(handle_physicalcpu);
static sysctl_handler(handle_physicalcpu_max);
static sysctl_handler(handle_logicalcpu);
static sysctl_handler(handle_logicalcpu_max);
static sysctl_handler(handle_memsize);
static sysctl_handler(handle_pagesize);
static sysctl_handler(handle_cputype);
static sysctl_handler(handle_cpusubtype);
static sysctl_handler(handle_cputhreadtype);
static sysctl_handler(handle_cpu64bitcapable);
static sysctl_handler(handle_machine);
static sysctl_handler(handle_cpufrequency);

static sysctl_handler(handle_physicalcpu);
static sysctl_handler(handle_physicalcpu_max);
static sysctl_handler(handle_logicalcpu);
static sysctl_handler(handle_logicalcpu_max);

// x86Sim: hw.perflevel0.* (one performance level holding every CPU; Apple silicon has two: P and E cores)
static const struct known_sysctl sysctls_hw_perflevel0[] = {
	{ .oid = 1, .type = CTLTYPE_INT, .exttype = "I", .name = "physicalcpu", .handler = handle_physicalcpu },
	{ .oid = 2, .type = CTLTYPE_INT, .exttype = "I", .name = "physicalcpu_max", .handler = handle_physicalcpu_max },
	{ .oid = 3, .type = CTLTYPE_INT, .exttype = "I", .name = "logicalcpu", .handler = handle_logicalcpu },
	{ .oid = 4, .type = CTLTYPE_INT, .exttype = "I", .name = "logicalcpu_max", .handler = handle_logicalcpu_max },
	{ .oid = 5, .type = CTLTYPE_INT, .exttype = "I", .name = "l1icachesize", .handler = handle_l1icachesize },
	{ .oid = 6, .type = CTLTYPE_INT, .exttype = "I", .name = "l1dcachesize", .handler = handle_l1dcachesize },
	{ .oid = 7, .type = CTLTYPE_INT, .exttype = "I", .name = "l2cachesize", .handler = handle_l2cachesize },
	{ .oid = 8, .type = CTLTYPE_INT, .exttype = "I", .name = "cpusperl2", .handler = handle_logicalcpu },
	{ .oid = 9, .type = CTLTYPE_STRING, .exttype = "S", .name = "name", .handler = handle_perflevel_name },
	{ .oid = -1 }
};

const struct known_sysctl sysctls_hw[] = {
	{ .oid = HW_AVAILCPU, .type = CTLTYPE_INT, .exttype = "", .name = "availcpu", .handler = handle_availcpu },
	{ .oid = HW_NCPU, .type = CTLTYPE_INT, .exttype = "", .name = "ncpu", .handler = handle_availcpu },
	// x86Sim: the cache and timebase keys (an M1's values) and the CPU topology Apple silicon apps read. H264SW (the
	// software H.264 encoder) aligned its buffers to hw.cachelinesize: with ENOENT that was 0, posix_memalign failed
	// (EINVAL), the half-built encoder freed its state and the next frame wrote through NULL (AVAssetWriter and
	// VTCompressionSession crashed).
	{ .oid = HW_CACHELINE, .type = CTLTYPE_QUAD, .exttype = "Q", .name = "cachelinesize", .handler = handle_cachelinesize },
	{ .oid = HW_L1ICACHESIZE, .type = CTLTYPE_QUAD, .exttype = "Q", .name = "l1icachesize", .handler = handle_l1icachesize },
	{ .oid = HW_L1DCACHESIZE, .type = CTLTYPE_QUAD, .exttype = "Q", .name = "l1dcachesize", .handler = handle_l1dcachesize },
	{ .oid = HW_L2CACHESIZE, .type = CTLTYPE_QUAD, .exttype = "Q", .name = "l2cachesize", .handler = handle_l2cachesize },
	{ .oid = HW_TB_FREQ, .type = CTLTYPE_QUAD, .exttype = "Q", .name = "tbfrequency", .handler = handle_tbfrequency },
	{ .oid = _HW_ACTIVECPU, .type = CTLTYPE_INT, .exttype = "I", .name = "activecpu", .handler = handle_availcpu },
	{ .oid = _HW_NPERFLEVELS, .type = CTLTYPE_INT, .exttype = "I", .name = "nperflevels", .handler = handle_nperflevels },
	{ .oid = _HW_PERFLEVEL0, .type = CTLTYPE_NODE, .exttype = "", .name = "perflevel0", .subctls = sysctls_hw_perflevel0 },
	{ .oid = _HW_PHYSICAL_CPU, .type = CTLTYPE_INT, .exttype = "", .name = "physicalcpu", .handler = handle_physicalcpu },
	{ .oid = _HW_PHYSICAL_CPU_MAX, .type = CTLTYPE_INT, .exttype = "", .name = "physicalcpu_max", .handler = handle_physicalcpu_max },
	{ .oid = _HW_LOGICAL_CPU, .type = CTLTYPE_INT, .exttype = "", .name = "logicalcpu", .handler = handle_logicalcpu },
	{ .oid = _HW_LOGICAL_CPU_MAX, .type = CTLTYPE_INT, .exttype = "", .name = "logicalcpu_max", .handler = handle_logicalcpu_max },
	{ .oid = HW_MEMSIZE, .type = CTLTYPE_QUAD, .exttype = "U", .name = "memsize", .handler = handle_memsize },
	{ .oid = HW_PAGESIZE, .type = CTLTYPE_INT, .exttype = "I", .name = "pagesize", .handler = handle_pagesize },
	{ .oid = _HW_CPUTYPE, .type = CTLTYPE_INT, .exttype = "", .name = "cputype", .handler = handle_cputype },
	{ .oid = _HW_CPUSUBTYPE, .type = CTLTYPE_INT, .exttype = "", .name = "cpusubtype", .handler = handle_cpusubtype },
	{ .oid = _HW_CPUTHREADTYPE, .type = CTLTYPE_INT, .exttype = "", .name = "cputhreadtype", .handler = handle_cputhreadtype },
	{ .oid = _HW_64BITCAPABLE, .type = CTLTYPE_INT, .exttype = "", .name = "cpu64bit_capable", .handler = handle_cpu64bitcapable },
	{ .oid = HW_MACHINE, .type = CTLTYPE_STRING, .exttype = "S", .name = "machine", .handler = handle_machine },
	{ .oid = _HW_CPUFREQUENCY, .type = CTLTYPE_INT, .exttype = "", .name = "cpufrequency", .handler = handle_cpufrequency },
	{ .oid = _HW_CPUFAMILY, .type = CTLTYPE_INT, .exttype = "I", .name = "cpufamily", .handler = handle_cpufamily },
	{ .oid = _HW_CPUSUBFAMILY, .type = CTLTYPE_INT, .exttype = "I", .name = "cpusubfamily", .handler = handle_cpusubfamily },
	{ .oid = _HW_OPTIONAL, .type = CTLTYPE_NODE, .exttype = "", .name = "optional", .subctls = sysctls_hw_optional },
	{ .oid = -1 }
};

static const struct host_basic_info* gethostinfo(void)
{
	static struct host_basic_info hinfo;

	if (!hinfo.avail_cpus)
	{
		mach_msg_type_number_t hcount = HOST_BASIC_INFO_COUNT;
		mach_port_t hself;

		hself = mach_host_self();
		host_info(hself, HOST_BASIC_INFO, &hinfo, &hcount);
		mach_port_deallocate(mach_task_self(), hself);
	}

	return &hinfo;
}

sysctl_handler(handle_availcpu)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = gethostinfo()->avail_cpus;
	return 0;
}

sysctl_handler(handle_physicalcpu)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = gethostinfo()->physical_cpu;
	return 0;
}

sysctl_handler(handle_physicalcpu_max)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = gethostinfo()->physical_cpu_max;
	return 0;
}

sysctl_handler(handle_logicalcpu)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = gethostinfo()->logical_cpu;
	return 0;
}

sysctl_handler(handle_logicalcpu_max)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = gethostinfo()->logical_cpu_max;
	return 0;
}

sysctl_handler(handle_memsize)
{

	sysctl_handle_size(sizeof(unsigned long long));
	*((unsigned long long*) old) = gethostinfo()->max_mem;
	return 0;
}

sysctl_handler(handle_pagesize)
{
	if (old == NULL)
	{
		*oldlen = sizeof(int);
		return 0;
	}
	else if (*oldlen < sizeof(int))
	{
		return -EINVAL;
	}
	else
	{
		*((int*) old) = 4096; // true on all Darling platforms

		// libc's sysconf passes in a `long` for the argument.
		// Apple's code is actually wrong there because it doesn't check the returned size.
		// to deal with this (since apparently it works on real macOS), what we do is zero out
		// the rest of the buffer so the upper half won't be garbage.
		//
		// note that this only works on little endian systems,
		// but that's okay; that's what all Darling platforms are.
		memset((char*)old + sizeof(int), 0, *oldlen - sizeof(int));

		*oldlen = sizeof(int);
	}
	return 0;
}

sysctl_handler(handle_cputype)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = X86SIM_ARM64() ? X86SIM_CPU_TYPE_ARM64 : gethostinfo()->cpu_type;
	return 0;
}

sysctl_handler(handle_cpusubtype)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = X86SIM_ARM64() ? X86SIM_CPU_SUBTYPE_ARM64E : gethostinfo()->cpu_subtype;
	return 0;
}

sysctl_handler(handle_cputhreadtype)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = gethostinfo()->cpu_threadtype;
	return 0;
}

sysctl_handler(handle_cpufrequency)
{
	int freq = 2400000;
	char buf[16];

	if (read_string("/sys/bus/cpu/devices/cpu0/cpufreq/cpuinfo_max_freq", buf, sizeof(buf)))
		freq = __simple_atoi(buf, NULL);
	*((int*) old) = freq;
	
	return 0;
}

sysctl_handler(handle_cpu64bitcapable)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = 1; // Darling only supports 64-bit CPUs
	return 0;
}

sysctl_handler(handle_machine)
{
	copyout_string(X86SIM_ARM64() ? "arm64" : need_uname()->machine, (char*) old, oldlen);
	return 0;
}

sysctl_handler(handle_cpufamily)
{
	if (!X86SIM_ARM64())
		return -ENOENT;
	sysctl_handle_size(sizeof(int));
	*((int*) old) = X86SIM_CPUFAMILY_ARM_FIRESTORM_ICESTORM;
	return 0;
}

sysctl_handler(handle_cpusubfamily)
{
	if (!X86SIM_ARM64())
		return -ENOENT;
	sysctl_handle_size(sizeof(int));
	*((int*) old) = 2; // CPUSUBFAMILY_ARM_HS (an M1's)
	return 0;
}

sysctl_handler(handle_optional_one)
{
	if (!X86SIM_ARM64())
		return -ENOENT;
	sysctl_handle_size(sizeof(int));
	*((int*) old) = 1;
	return 0;
}

sysctl_handler(handle_optional_zero)
{
	if (!X86SIM_ARM64())
		return -ENOENT;
	sysctl_handle_size(sizeof(int));
	*((int*) old) = 0;
	return 0;
}

// x86Sim: XNU's are 64-bit ("Q"); a caller with a 4-byte buffer gets an int (sysconf and older code pass one)
static long flex64(void* old, unsigned long* oldlen, unsigned long long v)
{
	if (old == NULL)
	{
		*oldlen = sizeof(unsigned long long);
		return 0;
	}
	if (*oldlen >= sizeof(unsigned long long))
	{
		*((unsigned long long*) old) = v;
		*oldlen = sizeof(unsigned long long);
	}
	else if (*oldlen >= sizeof(int))
	{
		*((int*) old) = (int) v;
		*oldlen = sizeof(int);
	}
	else
		return -EINVAL;
	return 0;
}

sysctl_handler(handle_cachelinesize) { return flex64(old, oldlen, 128); }
sysctl_handler(handle_l1icachesize) { return flex64(old, oldlen, 131072); }
sysctl_handler(handle_l1dcachesize) { return flex64(old, oldlen, 65536); }
sysctl_handler(handle_l2cachesize) { return flex64(old, oldlen, 4194304); }
sysctl_handler(handle_tbfrequency) { return flex64(old, oldlen, 24000000); }

sysctl_handler(handle_nperflevels)
{
	sysctl_handle_size(sizeof(int));
	*((int*) old) = 1;
	return 0;
}

sysctl_handler(handle_perflevel_name)
{
	copyout_string("Performance", (char*) old, oldlen);
	return 0;
}
