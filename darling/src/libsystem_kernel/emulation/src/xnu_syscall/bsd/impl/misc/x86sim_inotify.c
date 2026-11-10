#include <sys/errno.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/x86sim_memfd.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <string.h>

// x86Sim: Darling-private syscall 598 (unused by XNU): Linux inotify for simulator processes. On a Mac,
// fseventsd reads the kernel's /dev/fsevents and serves com.apple.FSEvents to every FSEvents client; the iOS
// simulator's FSEvents.framework talks to the host's fseventsd. Our stand-in (x86sim host/fseventsd, a simulator
// job) needs file names of changes, which kqueue vnode filters don't give, so it watches with inotify. Simulator
// processes link the runtime's libsystem_kernel, which has no way to reach Darling's __linux_inotify_* exports;
// this syscall is that way. Paths are Darling paths (vchroot-expanded here); the inotify fd is a plain Linux fd
// whose events are read with read(2).
//   op 0: inotify_init1(a1 = Linux flags)          -> fd
//   op 1: inotify_add_watch(a1 = fd, a2 = path, a3 = Linux mask) -> watch descriptor
//   op 2: inotify_rm_watch(a1 = fd, a2 = wd)       -> 0
long sys_x86sim_inotify(uint32_t op, uint64_t a1, uint64_t a2, uint64_t a3)
{
	long rv;
	switch (op)
	{
		case 0:
			rv = LINUX_SYSCALL(__NR_inotify_init1, (int) a1);
			break;
		case 1:
		{
			struct vchroot_expand_args vc;
			const char* path = (const char*) a2;
			if (!path)
				return -EFAULT;
			vc.flags = 0;
			vc.dfd = get_perthread_wd();
			strncpy(vc.path, path, sizeof(vc.path) - 1);
			vc.path[sizeof(vc.path) - 1] = 0;
			rv = vchroot_expand(&vc);
			if (rv < 0)
				return errno_linux_to_bsd(rv);
			rv = LINUX_SYSCALL(__NR_inotify_add_watch, (int) a1, vc.path, (uint32_t) a3);
			break;
		}
		case 2:
			rv = LINUX_SYSCALL(__NR_inotify_rm_watch, (int) a1, (int) a2);
			break;
		default:
			return -EINVAL;
	}
	if (rv < 0)
		return errno_linux_to_bsd(rv);
	return rv;
}
