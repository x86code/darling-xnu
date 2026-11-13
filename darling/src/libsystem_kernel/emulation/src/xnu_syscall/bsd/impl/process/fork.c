#include <darling/emulation/xnu_syscall/bsd/impl/psynch/ulock_wait.h> // x86Sim
#include <darling/emulation/xnu_syscall/bsd/impl/process/fork.h>

#include <_libkernel_init.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchdir.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/other/mach/foreign_hook.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/socktables.h>

#include <darlingserver/rpc.h>

extern _libkernel_functions_t _libkernel_functions;

// x86Sim (2026-11-13): libkqueue's child reset (libkqueue common/kqueue.c). Darling's libSystem.B (its libkqueue)
// overrides this weak default; the simulator's libkqueue_sim is reached by its foreign hook. Both are called first
// in the child, before guard_table_postfork_child closes descriptors (close() -> kqueue_closed_fd takes their locks).
__attribute__((weak))
__attribute__((visibility("default")))
void kqueue_atfork_child_reset(void)
{
}

// the simulator's hook is looked up in the parent (a dlsym through the guest's dyld takes its locks: not in the child)
static void (*sim_kqueue_child_reset)(void);
static int sim_kqueue_child_reset_resolved;

static void kqueue_child_reset_resolve(void)
{
#ifndef VARIANT_DYLD
	if (!sim_kqueue_child_reset_resolved) {
		sim_kqueue_child_reset = (void (*)(void)) darling_foreign_hook("__darling_sim_kqueue_atfork_child");
		sim_kqueue_child_reset_resolved = 1;
	}
#endif
}

static void kqueue_child_reset_all(void)
{
	kqueue_atfork_child_reset();
	if (sim_kqueue_child_reset)
		sim_kqueue_child_reset();
}

long sys_fork(void)
{
	int ret;
	int wdfd = get_perthread_wd();
	kqueue_child_reset_resolve();

#ifdef SYS_fork
	ret = LINUX_SYSCALL(__NR_fork);
#else
	ret = LINUX_SYSCALL(__NR_clone, LINUX_SIGCHLD, 0);
#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else if (ret == 0)
	{
		// in the child

		// x86Sim (2026-11-13): mldr's locks first (elfcalls.h postfork_child): the guard table below closes the
		// parent's descriptors through mldr's socket bitmap, whose lock another thread may have held at the fork
		__darling_elf_postfork_child();
		kqueue_child_reset_all();

		// the old RPC FD will be closed in `guard_table_postfork_child`;
		// we don't need to close it ourselves.
		// that should also take care of closing descriptors for any other threads.
		guard_table_postfork_child();
		// x86Sim: willi/darling-xnu#7/#8: PF_ROUTE answering ends, held socket errors, SO_NOSIGPIPE flags and their locks
		socket_tables_atfork_child();
		ulock_atfork_child(); // x86Sim: no waiters in the child

		// create a new dserver RPC socket
		__dserver_per_thread_socket_refresh();
		int newReadFd = __dserver_process_lifetime_pipe_refresh();

		// guard it
		guard_entry_options_t options;
		options.close = __dserver_close_socket;
		guard_table_add(__dserver_per_thread_socket(), guard_flag_prevent_close | guard_flag_close_on_fork, &options);

		// only guard the lifetime pipe if it's used.
		if (newReadFd != -1)
		{
			options.close = __dserver_close_process_lifetime_pipe;
			guard_table_add(__dserver_get_process_lifetime_pipe(), guard_flag_prevent_close | guard_flag_close_on_fork, &options);
		}

		int dummy_stack_variable;
		if (dserver_rpc_checkin(true, &dummy_stack_variable, newReadFd) < 0) {
			// we can't do ANYTHING if darlingserver fails to acknowledge us
			__simple_printf("Failed to checkin with darlingserver after fork\n");
			__simple_abort();
		}
		if (wdfd >= 0)
			sys_fchdir(wdfd);

		__dserver_close_process_lifetime_pipe(newReadFd);
	}
	else
	{
		// The child inherits our special ports (e.g. the bootstrap port) when it
		// checks in with darlingserver, so we must not return before that.
		// Only a fork that created a child waits: no child checks in after a
		// failed one.
		while (dserver_rpc_fork_wait_for_child() == -LINUX_EINTR)
			;
	}

	return ret;
}
