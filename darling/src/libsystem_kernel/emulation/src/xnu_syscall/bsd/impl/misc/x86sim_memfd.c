#include <darling/emulation/xnu_syscall/bsd/impl/misc/x86sim_memfd.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darlingserver/rpc.h>

// x86Sim: Darling-private syscall 599 (unused by XNU): a Linux fd for the memfd behind
// [address, address + size) of this process (darlingserver makes the range a shared memfd mapping first if
// it isn't one). The fd can be passed to native Linux processes with SCM_RIGHTS: spike3/metal's metalhostd
// hands MTLBuffer pages to mtlvk this way. Returns the fd; *out_offset is address's byte offset in the memfd,
// *out_shared 0 if the fd is only a snapshot of the range (a file mapping).
long sys_x86sim_memfd_for_region(uint64_t address, uint64_t size, uint64_t* out_offset, uint32_t* out_shared)
{
	int fd = -1;
	uint64_t offset = 0;
	uint32_t shared = 0;
	int ret = dserver_rpc_x86sim_memfd_for_region(address, size, &fd, &offset, &shared);

	if (ret < 0)
		return errno_linux_to_bsd(ret);
	if (out_offset)
		*out_offset = offset;
	if (out_shared)
		*out_shared = shared;
	return fd;
}

// x86Sim: __work_interval_ctl (BSD syscall 499) was missing (ENOSYS). UIKit creates a work interval for its
// scroll/animation frame pacing (-[_UIUpdateCycle...] -> work_interval_create) and throws
// "Failed to create work interval" when that fails: every app aborted on its first scroll. There is no scheduler
// to tell about work intervals here, so every operation succeeds: CREATE2 hands out ids (no port), the rest
// (destroy, notify, join, get flags) do nothing.
struct x86sim_work_interval_create_params {
	uint64_t wicp_id;
	uint32_t wicp_port;
	uint32_t wicp_create_flags;
};

long sys_work_interval_ctl(uint32_t operation, uint64_t work_interval_id, void* arg, uint64_t len)
{
	static uint64_t next_id = 1;
	struct x86sim_work_interval_create_params* p = arg;

	switch (operation) {
	case 4: // WORK_INTERVAL_OPERATION_CREATE2
		if (!p || len < sizeof(*p))
			return -22; // EINVAL
		p->wicp_id = __atomic_fetch_add(&next_id, 1, __ATOMIC_RELAXED);
		p->wicp_port = 0;
		return 0;
	case 9: // WORK_INTERVAL_OPERATION_GET_FLAGS
		if (p && len >= sizeof(*p))
			p->wicp_create_flags = 0;
		return 0;
	default:
		return 0;
	}
}
