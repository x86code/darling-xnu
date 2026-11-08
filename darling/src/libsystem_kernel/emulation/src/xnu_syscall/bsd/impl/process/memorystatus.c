// x86Code (RAM 2): jetsam bands and dirty tracking, recorded for the Linux-side jetsam (cli/libexec/jetsam.py).
//
// A device's memorystatus keeps each process in a priority band: launchd puts a daemon's band in its spawn attributes
// (posix_spawnattr_setjetsam_ext), RunningBoard moves apps and extensions between bands as they go foreground,
// background or suspended (memorystatus_control MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES), and a daemon that launchd
// lets exit when clean (EnablePressuredExit) is dirty-tracked (proc_track_dirty / proc_set_dirty, PROC_INFO_CALL_DIRTYCONTROL):
// while it is clean with PROC_DIRTY_ALLOWS_IDLE_EXIT the kernel holds it in the idle band, and jetsam kills the idle
// band first when memory runs short. All of this returned 0 and did nothing here, so nothing was ever reclaimed: an
// app in the background that RunningBoard never suspended (Maps) and every daemon a boot's launch events started
// (Siri's, Wallet's, ~1 GB) stayed resident.
//
// Recorded per process as /private/var/run/x86code-jetsam/<pid> (rewritten at each change; mtime = when), one line:
//     <priority> <dirty flags> <user_data> <darwin bg> <darwin role>
// priority -1 = never set; dirty flags = PROC_DIRTY_TRACKED|ALLOWS_IDLE_EXIT|IS_DIRTY as proc_get_dirty reports them;
// darwin bg = 1 while RunningBoard has the process backgrounded (setpriority PRIO_DARWIN_PROCESS, PRIO_DARWIN_BG),
// 0 once it is brought back, -1 never set; darwin role = setpriority(PRIO_DARWIN_ROLE) (UI_FOCAL 1, UI 2, NON_UI 3 =
// off screen, UI_NON_FOCAL 4, TAL_LAUNCH 5, DARWIN_BG 6; -1 never set). (The simulator's RunningBoard sets no jetsam bands: this is how an app that
// is in the background but not suspended, e.g. Maps, is told from the foreground one.)
// jetsam.py applies the policy (which bands to reclaim, when). The directory is cleared at each boot (boot-a64.sh).
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getpid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkdir.h>
#include <stdint.h>
#include <sys/errno.h>

#define JS_DIR "/private/var/run/x86code-jetsam"

// proc_info.h (PRIVATE)
#define DC_TRACK 1
#define DC_SET 2
#define DC_GET 3
#define DC_CLEAR 4
#define PD_TRACK 0x1
#define PD_ALLOW_IDLE_EXIT 0x2
#define PD_DEFER 0x4
#define PD_DEFER_ALWAYS 0x10
#define PD_TRACKED 0x1
#define PD_ALLOWS_IDLE_EXIT 0x2
#define PD_IS_DIRTY 0x4

struct js_state { long priority; long dirty; uint64_t user_data; long bg; long role; };

static void js_path(char* path, int pid)
{
	__simple_sprintf(path, JS_DIR "/%d", pid);
}

static long parse_num(const char** p)
{
	long v = 0, neg = 0;
	while (**p == ' ' || **p == '\n') (*p)++;
	if (**p == '-') { neg = 1; (*p)++; }
	while (**p >= '0' && **p <= '9') { v = v * 10 + (**p - '0'); (*p)++; }
	return neg ? -v : v;
}

static void js_read(int pid, struct js_state* st)
{
	char path[96], buf[96];
	st->priority = -1;
	st->dirty = 0;
	st->user_data = 0;
	st->bg = -1;
	st->role = -1;
	js_path(path, pid);
	long fd = sys_openat(-2 /* AT_FDCWD */, path, 0 /* O_RDONLY */, 0);
	if (fd < 0)
		return;
	long n = sys_read(fd, buf, sizeof(buf) - 1);
	sys_close(fd);
	if (n <= 0)
		return;
	buf[n] = 0;
	const char* p = buf;
	st->priority = parse_num(&p);
	st->dirty = parse_num(&p);
	st->user_data = (uint64_t)parse_num(&p);
	while (*p == ' ') p++;
	if ((*p >= '0' && *p <= '9') || *p == '-')
		st->bg = parse_num(&p);
	while (*p == ' ') p++;
	if ((*p >= '0' && *p <= '9') || *p == '-')
		st->role = parse_num(&p);
}

static void js_write(int pid, const struct js_state* st)
{
	char path[96], buf[96];
	js_path(path, pid);
	long fd = sys_openat(-2, path, 0x1 | 0x200 | 0x400 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
	if (fd == -2 /* ENOENT: no directory yet */)
	{
		sys_mkdir(JS_DIR, 0755);
		fd = sys_openat(-2, path, 0x1 | 0x200 | 0x400, 0644);
	}
	if (fd < 0)
		return;
	__simple_sprintf(buf, "%d %d %d %d %d\n", (int)st->priority, (int)st->dirty, (int)st->user_data, (int)st->bg,
		(int)st->role);
	sys_write(fd, buf, __simple_strlen(buf));
	sys_close(fd);
}

// posix_spawn's child (attributes with POSIX_SPAWN_JETSAM_SET): the band launchd gave the job.
void x86code_jetsam_spawned(int priority)
{
	struct js_state st;
	int pid = (int)sys_getpid();
	js_read(pid, &st);
	st.priority = priority;
	js_write(pid, &st);
}

// x86Code: memorystatus_control (440). Every command succeeds and queries report nothing (0 bytes), as before
// (failing it made the user containermanagerd crash at startup); a band change is recorded.
long sys_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void* buffer, unsigned long size)
{
	if (command != 2)
		x86code_unsupported("memorystatus_control", command); // census: answered 0 / nothing
	// Align 1: the simulator's kernel is macOS's, built without CONFIG_JETSAM: memorystatus_control
	// (bsd/kern/kern_memorystatus.c) has no case for these there and fails them with EINVAL. RunningBoard asks
	// CONVERT_MEMLIMIT_MB (28) for its processes' limits: the 0 we answered read as a 0 MB limit.
	switch (command)
	{
		case 5:  // MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK
		case 6:  // MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT
		case 25: // MEMORYSTATUS_CMD_MARK_PROCESS_COALITION_SWAPPABLE
		case 26: // MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE
		case 28: // MEMORYSTATUS_CMD_CONVERT_MEMLIMIT_MB
		case 36: // MEMORYSTATUS_CMD_REARM_MEMLIMIT
			return -EINVAL;
	}
	if (command == 2 /* MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES */ && pid > 0 && buffer != 0 && size >= 16)
	{
		struct { int32_t priority; uint64_t user_data; } const* pp = buffer;
		struct js_state st;
		js_read(pid, &st);
		if (st.priority != pp->priority)
		{
			st.priority = pp->priority;
			st.user_data = pp->user_data;
			js_write(pid, &st);
		}
	}
	return 0;
}

// proc_info(PROC_INFO_CALL_DIRTYCONTROL, pid, flavor, arg, buffer, buffersize): proc_track_dirty, proc_set_dirty,
// proc_get_dirty, proc_clear_dirty.
// A process's own proc_set_dirty runs at each XPC transaction edge: the last value it set is kept (per pid, so a
// fork child starts over), and setting the same value again does no file I/O.
static int self_pid;
static int self_dirty = -1;

long x86code_dirtycontrol(int32_t pid, uint32_t flavor, uint64_t arg, void* buffer, int32_t bufsize)
{
	struct js_state st;
	int me = (int)sys_getpid();
	if (pid <= 0)
		pid = me;
	if (flavor == DC_SET && pid == me && self_pid == me && self_dirty == (arg ? 1 : 0))
		return 0;
	js_read(pid, &st);
	long was = st.dirty;
	switch (flavor)
	{
		case DC_TRACK:
			st.dirty = (st.dirty & PD_IS_DIRTY) | ((arg & PD_TRACK) ? PD_TRACKED : 0)
				| ((arg & PD_ALLOW_IDLE_EXIT) ? PD_ALLOWS_IDLE_EXIT : 0);
			break;
		case DC_SET:
			// xnu fails this with EINVAL for an untracked process; it always succeeded here, and still does (the
			// bit is recorded, jetsam.py only acts on tracked processes)
			st.dirty = arg ? (st.dirty | PD_IS_DIRTY) : (st.dirty & ~PD_IS_DIRTY);
			if (pid == me)
			{
				self_pid = me;
				self_dirty = arg ? 1 : 0;
			}
			break;
		case DC_GET:
			if (buffer == 0 || bufsize < 4)
				return -EINVAL;
			*(uint32_t*)buffer = (uint32_t)st.dirty;
			return 0;
		case DC_CLEAR:
			st.dirty &= ~(long)(arg & (PD_TRACKED | PD_ALLOWS_IDLE_EXIT | PD_IS_DIRTY));
			break;
		default:
			return -EINVAL;
	}
	if (st.dirty != was)
		js_write(pid, &st);
	return 0;
}

// setpriority(PRIO_DARWIN_PROCESS, pid, prio) (process/setpriority.c): RunningBoard backgrounds (PRIO_DARWIN_BG) and
// foregrounds (0) the processes it manages.
void x86code_jetsam_darwin_bg(int pid, int prio)
{
	struct js_state st;
	if (pid <= 0)
		pid = (int)sys_getpid();
	js_read(pid, &st);
	long bg = (prio & 0x1000 /* PRIO_DARWIN_BG */) ? 1 : 0;
	if (st.bg != bg)
	{
		st.bg = bg;
		js_write(pid, &st);
	}
}

// setpriority(PRIO_DARWIN_ROLE, pid, role): the task role RunningBoard gives an app (foreground, background, ...).
void x86code_jetsam_darwin_role(int pid, int role)
{
	struct js_state st;
	if (pid <= 0)
		pid = (int)sys_getpid();
	js_read(pid, &st);
	if (st.role != role)
	{
		st.role = role;
		js_write(pid, &st);
	}
}

// Align 1: syscalls the runtime makes that had no entry ("Unimplemented syscall", ENOSYS; census at boot).
// quotactl (165, searchd): no volume here has quotas: ENOTSUP, as XNU's quotactl for a mount without them.
long sys_x86code_quotactl(void)
{
	return -ENOTSUP;
}

// proc_rlimit_control (446, coreaudiod & co.): wakeup / CPU / footprint-interval monitors (bsd/kern/kern_resource.c).
// Nothing monitors here: accepted (0), as XNU does for a valid flavor; an unknown flavor is EINVAL.
long sys_x86code_proc_rlimit_control(int pid, int flavor, void* arg)
{
	if (flavor < 0 || flavor > 7)
		return -EINVAL;
	return 0;
}

// telemetry (451, runningboardd): no telemetry subsystem: ENOTSUP (XNU without CONFIG_TELEMETRY).
long sys_x86code_telemetry(void)
{
	return -ENOTSUP;
}

// thread_selfusage (482, searchd): the calling thread's CPU time in mach time units (XNU thread_get_runtime_self);
// Darling's mach time is nanoseconds (CLOCK_MONOTONIC), so CLOCK_THREAD_CPUTIME_ID (3) in ns.
uint64_t sys_x86code_thread_selfusage(void)
{
	struct { long tv_sec; long tv_nsec; } ts;
	if (LINUX_SYSCALL(__NR_clock_gettime, 3, &ts) < 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
