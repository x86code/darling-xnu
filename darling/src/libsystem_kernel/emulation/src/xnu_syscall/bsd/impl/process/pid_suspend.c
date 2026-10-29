// x86Code: pid_suspend (433) and pid_resume (434).
//
// RunningBoard suspends idle extensions and background apps with pid_suspend() and resumes them with pid_resume()
// before giving them work. Both returned ENOSYS here ("pid_suspend() failed with error 78", ~10,000 times a boot),
// so nothing was ever suspended: every widget extension, poster and background app kept running its run loops and
// timers. They map onto task_suspend()/task_resume() of the target's task (darlingserver stops its threads).
//
// A device then reclaims suspended processes with jetsam when memory runs short; the simulator has no jetsam (and
// every process here carries ~200 MB of private framework data: no dyld shared cache). So each suspension is also
// recorded as /private/var/run/x86code-suspended/<pid> (mtime = when), removed on resume; cli/libexec/jetsam.py kills
// extensions and older background apps that stay suspended (the policy lives there, on the Linux side).
#include <darling/emulation/xnu_syscall/bsd/impl/process/pid_suspend.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/unlink.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkdir.h>
#include <mach/mach.h>
#include <sys/errno.h>

#define SUSP_DIR "/private/var/run/x86code-suspended"

static void suspend_marker(int pid, int set)
{
	char path[96];
	__simple_sprintf(path, SUSP_DIR "/%d", pid);
	if (!set)
	{
		sys_unlink(path);
		return;
	}
	long fd = sys_openat(-2 /* AT_FDCWD */, path, 0x1 | 0x200 | 0x400 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
	if (fd == -2 /* ENOENT: no directory yet */)
	{
		sys_mkdir(SUSP_DIR, 0755);
		fd = sys_openat(-2, path, 0x1 | 0x200 | 0x400, 0644);
	}
	if (fd >= 0)
		sys_close(fd);
}

static long pid_task_op(int pid, int suspend)
{
	mach_port_name_t task = MACH_PORT_NULL;
	if (pid <= 0)
		return -EINVAL;
	if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS || task == MACH_PORT_NULL)
		return -ESRCH;
	kern_return_t kr = suspend ? task_suspend(task) : task_resume(task);
	mach_port_deallocate(mach_task_self(), task);
	if (kr != KERN_SUCCESS)
		return (kr == KERN_FAILURE) ? -EINVAL : -ESRCH;
	suspend_marker(pid, suspend);
	return 0;
}

long sys_pid_suspend(int pid)
{
	return pid_task_op(pid, 1);
}

long sys_pid_resume(int pid)
{
	return pid_task_op(pid, 0);
}
