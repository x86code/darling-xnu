#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/workq_kernreturn.h>

#include <sys/errno.h>
#include <stddef.h>
#include <sys/queue.h>
#include <os/lock.h>
#include <pthread/tsd_private.h>

#define __PTHREAD_EXPOSE_INTERNALS__ 1
#include <pthread/priority_private.h>

#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_register.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_create.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/ext/futex.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/machdep/impl/tls.h>
#include <darling/emulation/xnu_syscall/mach/impl/mach_traps.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>

#include <elfcalls/threads.h>
#include <darlingserver/rpc.h>

// much easier to include than libpthread's `internal.h`
#include <darling/mldr/elfcalls/dthreads.h>
#include <darling/emulation/common/tsd.h>

#define WQ_MAX_THREADS	64

#define WQOPS_QUEUE_ADD 1
#define WQOPS_QUEUE_REMOVE 2
#define WQOPS_THREAD_RETURN 4
#define WQOPS_THREAD_SETCONC  8
#define WQOPS_THREAD_KEVENT_RETURN 0x40
#define WQOPS_THREAD_WORKLOOP_RETURN 0x100
#define WQOPS_QUEUE_NEWSPISUPP  0x10
#define WQOPS_QUEUE_REQTHREADS  0x20
#define WQOPS_QUEUE_REQTHREADS2    0x30
#define WQOPS_SET_EVENT_MANAGER_PRIORITY 0x80
#define WQOPS_SETUP_DISPATCH 0x400

// Flags for the newly spawned thread:
// WQ_FLAG_THREAD_NEWSPI
// WQ_FLAG_THREAD_REUSE (0 if thread is newly spawned)
// item is unused in "new SPI"

#define WQ_FLAG_THREAD_PRIO_SCHED    0x00008000
#define WQ_FLAG_THREAD_PRIO_QOS      0x00004000
#define WQ_FLAG_THREAD_PRIO_MASK     0x00000fff

#define WQ_FLAG_THREAD_OVERCOMMIT    0x00010000
#define WQ_FLAG_THREAD_REUSE         0x00020000
#define WQ_FLAG_THREAD_NEWSPI        0x00040000
#define WQ_FLAG_THREAD_KEVENT        0x00080000
#define WQ_FLAG_THREAD_EVENT_MANAGER 0x00100000
#define WQ_FLAG_THREAD_TSD_BASE_SET  0x00200000
#define WQ_FLAG_THREAD_WORKLOOP      0x00400000
#define WQ_FLAG_THREAD_OUTSIDEQOS    0x00800000
// x86Code: Swift concurrency's cooperative pool (XNU: WQOPS_QUEUE_REQTHREADS2 asks for these)
#define WQ_FLAG_THREAD_COOPERATIVE   0x01000000
#ifndef _PTHREAD_PRIORITY_COOPERATIVE_FLAG
#define _PTHREAD_PRIORITY_COOPERATIVE_FLAG 0x08000000u
#endif

#define WORKQ_EXIT_THREAD_NKEVENT (-1)

static int workq_sem = WQ_MAX_THREADS; // max 64 threads in use
// x86Code: constrained (not overcommit / kevent / workloop / event manager) threads in use, see wq_spawn
static int workq_constrained_sem = WQ_MAX_THREADS;
static os_unfair_lock workq_parked_lock = OS_UNFAIR_LOCK_INIT;
// static int workq_parked_threads = 0; // num spawned, but unused threads
static int workq_parked[WQ_MAX_THREADS];
static int workq_parked_prio[WQ_MAX_THREADS];

TAILQ_HEAD(tailhead, parked_thread) workq_parked_head = TAILQ_HEAD_INITIALIZER(workq_parked_head);

struct parked_thread
{
	int sem, flags;
	struct wq_kevent_data* event;
	TAILQ_ENTRY(parked_thread) entries;
};

static void list_add(struct parked_thread* head, struct parked_thread* item);
static void list_remove(struct parked_thread* head, struct parked_thread* item);

struct timespec
{
	long tv_sec;
	long tv_nsec;
};

// x86Code: libsystem_kernel must not export os_unfair_lock_{lock,unlock}: its weak
// stubs shadowed libsystem_platform's real locks for foreign libSystems (iOS simulator).
// Use libsimple's lock here instead (same 32-bit, zero-initialised layout).
#include <libsimple/lock.h>
_Static_assert(sizeof(os_unfair_lock) == sizeof(libsimple_lock_t), "lock layout");
static void darling_unfair_lock_lock(os_unfair_lock_t lock) { libsimple_lock_lock((libsimple_lock_t*) lock); }
static void darling_unfair_lock_unlock(os_unfair_lock_t lock) { libsimple_lock_unlock((libsimple_lock_t*) lock); }
#define os_unfair_lock_lock darling_unfair_lock_lock
#define os_unfair_lock_unlock darling_unfair_lock_unlock

//void* __attribute__((weak)) __attribute__((visibility("default"))) pthread_getspecific(unsigned long key) { return NULL; }
//int __attribute__((weak)) __attribute__((visibility("default"))) pthread_setspecific(unsigned long key, const void* value) { return 1; }

static int priority_to_class(int prio);

// This is horrible, but it may work
static struct wq_kevent_data* wq_event_pending = NULL;

// x86Code: kevent batches handed to workqueue threads, matched on return by the
// events pointer (libpthread passes the same keventlist back). The single
// wq_event_pending above gets overwritten by ordinary thread requests.
static struct wq_kevent_data* wq_events_inflight[WQ_MAX_THREADS];
static libsimple_lock_t wq_events_inflight_lock = LIBSIMPLE_LOCK_INITIALIZER;

static void wq_event_inflight_add(struct wq_kevent_data* ev)
{
	int i;
	libsimple_lock_lock(&wq_events_inflight_lock);
	for (i = 0; i < WQ_MAX_THREADS; i++)
	{
		if (wq_events_inflight[i] == NULL)
		{
			wq_events_inflight[i] = ev;
			break;
		}
	}
	libsimple_lock_unlock(&wq_events_inflight_lock);
}

static struct wq_kevent_data* wq_event_inflight_take(const void* events)
{
	struct wq_kevent_data* ev = NULL;
	int i;
	libsimple_lock_lock(&wq_events_inflight_lock);
	for (i = 0; i < WQ_MAX_THREADS; i++)
	{
		ev = wq_events_inflight[i];
		if (ev != NULL && (ev->events == events || ((const char*) events >= (const char*) ev->events
				&& (const char*) events < (const char*) (ev->events + ev->capacity))))
		{
			wq_events_inflight[i] = NULL;
			break;
		}
		ev = NULL;
	}
	libsimple_lock_unlock(&wq_events_inflight_lock);
	return ev;
}

static void rpc_guard(int fd) {
	guard_entry_options_t options;
	options.close = __dserver_close_socket;
	guard_table_add(fd, guard_flag_prevent_close | guard_flag_close_on_fork, &options);
};

static void rpc_unguard(int fd) {
	guard_table_remove(fd);
};

static const struct darling_thread_create_callbacks callbacks = {
	.thread_self_trap = &thread_self_trap_impl,
	.thread_set_tsd_base = &sys_thread_set_tsd_base,
	.rpc_guard = rpc_guard,
	.rpc_unguard = rpc_unguard,
};

static int extract_wq_flags(int priority) {
	int flags = 0;
	int qos = _pthread_priority_thread_qos(priority);

	flags = WQ_FLAG_THREAD_NEWSPI | qos | WQ_FLAG_THREAD_PRIO_QOS;

	// Events for knotes registered at the event-manager priority go to the
	// event manager thread (kevent workq, see kevent_qos.c)
	if (priority & _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG) {
		flags = WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_EVENT_MANAGER;
	}

	if (priority & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG) {
		flags |= WQ_FLAG_THREAD_OVERCOMMIT;
	}

	// x86Code: a cooperative pool thread stays one when it is parked and reused
	if (priority & _PTHREAD_PRIORITY_COOPERATIVE_FLAG) {
		flags |= WQ_FLAG_THREAD_COOPERATIVE;
	}

	return flags;
};

#ifndef VARIANT_DYLD
static bool wq_flags_constrained(uintptr_t flags)
{
	return !(flags & (WQ_FLAG_THREAD_OVERCOMMIT | WQ_FLAG_THREAD_KEVENT | WQ_FLAG_THREAD_WORKLOOP | WQ_FLAG_THREAD_EVENT_MANAGER));
}

static void wq_cap_init(void)
{
	extern bool darling_x86code_arm64;
	static int capped;
	if (darling_x86code_arm64 && !__atomic_exchange_n(&capped, 1, __ATOMIC_ACQ_REL))
		__atomic_fetch_sub(&workq_constrained_sem, WQ_MAX_THREADS - 24, __ATOMIC_ACQ_REL);
}

static int sem_trydown(int* sem)
{
	int v = __atomic_load_n(sem, __ATOMIC_ACQUIRE);
	while (v > 0)
	{
		if (__atomic_compare_exchange_n(sem, &v, v - 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			return 1;
	}
	return 0;
}

static void wq_start_one(int flags, struct wq_kevent_data* wq_event);

// x86Code (Speed 17): on arm64 a constrained request made while the capped constrained pool is full is queued here,
// as XNU queues it, instead of blocking the requester in sem_down. A requester blocked there could be a worker the
// pool was waiting for: geod again sat with 24 workers in futex waits and Maps' main thread black for good (Speed 17
// run fb). A worker whose run ends, and every new request, start queued ones while a constrained slot is free.
static libsimple_lock_t wq_cpend_lock = LIBSIMPLE_LOCK_INITIALIZER;
static int wq_cpend_flags[WQ_MAX_THREADS * 4];
static int wq_cpend_n = 0;

static void wq_cpend_drain(void)
{
	for (;;)
	{
		int f;
		libsimple_lock_lock(&wq_cpend_lock);
		if (wq_cpend_n == 0 || !sem_trydown(&workq_constrained_sem))
		{
			libsimple_lock_unlock(&wq_cpend_lock);
			return;
		}
		f = wq_cpend_flags[0];
		for (int k = 1; k < wq_cpend_n; k++)
			wq_cpend_flags[k - 1] = wq_cpend_flags[k];
		wq_cpend_n--;
		libsimple_lock_unlock(&wq_cpend_lock);
		wq_start_one(f, NULL);
	}
}

// x86Code: wake a parked workqueue thread (or create one) per requested thread
static void wq_spawn(int flags, struct wq_kevent_data* wq_event, int affinity)
{
	int i;

	// x86Code: arm64 simulator processes (every thread runs a JIT with its own code cache and translation state,
	// ~20 MB) get at most 24 constrained workqueue threads instead of 64: a slow JIT let backlogs grow
	// launchd_sim to 66 threads and the boot past its memory budget.
	// Speed 15: the cap covers constrained requests only, as XNU's constrained pool does. Overcommit, kevent,
	// workloop and event manager requests (XPC replies, dispatch_sync wakeups, serial queues) keep the 64 thread
	// limit. With them under the cap too, the requester (here blocking in sem_down, where XNU queues the request)
	// deadlocked once 24 workers sat in synchronous XPC waits whose replies needed one more thread: geod at Maps'
	// first open (its main thread waits in GEOConfigGetDictionary), black for ~60 s.
	wq_cap_init();
	const bool constrained = wq_flags_constrained(flags);

	extern bool darling_x86code_arm64;
	for (i = 0; i < affinity; i++)
	{
		// Increase the amount of running threads
		if (constrained && darling_x86code_arm64 && wq_event == NULL)
		{
			libsimple_lock_lock(&wq_cpend_lock);
			if (wq_cpend_n < (int) (sizeof(wq_cpend_flags) / sizeof(wq_cpend_flags[0])))
			{
				wq_cpend_flags[wq_cpend_n++] = flags;
				libsimple_lock_unlock(&wq_cpend_lock);
				wq_cpend_drain();
				continue;
			}
			libsimple_lock_unlock(&wq_cpend_lock);
		}
		if (constrained)
			sem_down(&workq_constrained_sem, -1);
		wq_start_one(flags, wq_event);
	}
}

static void wq_start_one(int flags, struct wq_kevent_data* wq_event)
{
	{
		sem_down(&workq_sem, -1);

		os_unfair_lock_lock(&workq_parked_lock);

		if (workq_parked_head.tqh_first != NULL)
		{
			struct parked_thread* thread;

			thread = workq_parked_head.tqh_first;

			// Resume an existing thread
			// __simple_printf("Resuming thread %d\n", id);

			thread->flags = flags;
			thread->event = wq_event;

			// Dequeue
			TAILQ_REMOVE(&workq_parked_head, thread, entries);

			// Resume the thread
			sem_up(&thread->sem);
			os_unfair_lock_unlock(&workq_parked_lock);

			return;
		}

		os_unfair_lock_unlock(&workq_parked_lock);

		// __simple_printf("Spawning a new thread, nevents=%d\n", (wq_event != NULL) ? wq_event->nevents : -1);
		if (wq_event != NULL)
			wq_event_pending = wq_event;

		__darling_thread_create(512*1024, pthread_obj_size, wqueue_entry_point_wrapper, 0,
				(wq_event != NULL) ? wq_event->events : NULL, flags,
				(wq_event != NULL) ? wq_event->nevents : 0,
				&callbacks, NULL);

		/*if (ret < 0)
		{
			__simple_printf("Failed to spawn a new thread, err %d\n", -ret);
			return ret;
		}*/
	}
}

// x86Code: XNU runs at most one event manager thread per process (the manager queue and
// libdispatch's muxnotes, mach-port/proc/signal knotes shared by several sources, are only
// touched there). We started one for every manager thread request: _dispatch_mgr_queue_poke
// (WQOPS_QUEUE_REQTHREADS) and kevent batches (WQOPS_QUEUE_REQTHREAD_FOR_KEVENT, kevent_qos.c)
// each got their own, so one thread unregistered a source (freeing it / its muxnote) while
// another merged an event for it: "API MISUSE: Resurrection of an object" in
// _dispatch_kevent_merge and SIGSEGVs on stale unotes (backboardd, when a client died).
// Requests made while a manager runs are queued and started when it returns.
static libsimple_lock_t wq_mgr_lock = LIBSIMPLE_LOCK_INITIALIZER;
static bool wq_mgr_active = false;
static bool wq_mgr_pending_plain = false;
static struct wq_kevent_data* wq_mgr_pending_kevent[WQ_MAX_THREADS];
static int wq_mgr_npending_kevent = 0;

static bool wq_mgr_claim(struct wq_kevent_data* wq_event)
{
	bool claimed = false;
	libsimple_lock_lock(&wq_mgr_lock);
	if (!wq_mgr_active)
		claimed = wq_mgr_active = true;
	else if (wq_event == NULL)
		wq_mgr_pending_plain = true;
	else if (wq_mgr_npending_kevent < WQ_MAX_THREADS)
		wq_mgr_pending_kevent[wq_mgr_npending_kevent++] = wq_event;
	else
	{
		__simple_printf("workq: too many pending event manager batches\n");
		claimed = true;
	}
	libsimple_lock_unlock(&wq_mgr_lock);
	return claimed;
}

// Called when an event manager thread finishes a run: start the next queued request
static void wq_mgr_release(void)
{
	struct wq_kevent_data* next = NULL;
	bool plain = false;
	int i;

	libsimple_lock_lock(&wq_mgr_lock);
	if (wq_mgr_npending_kevent > 0)
	{
		next = wq_mgr_pending_kevent[0];
		for (i = 1; i < wq_mgr_npending_kevent; i++)
			wq_mgr_pending_kevent[i - 1] = wq_mgr_pending_kevent[i];
		wq_mgr_npending_kevent--;
	}
	else if (wq_mgr_pending_plain)
	{
		wq_mgr_pending_plain = false;
		plain = true;
	}
	else
		wq_mgr_active = false;
	libsimple_lock_unlock(&wq_mgr_lock);

	if (next != NULL)
		wq_spawn(WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_EVENT_MANAGER | WQ_FLAG_THREAD_KEVENT, next, 1);
	else if (plain)
		wq_spawn(WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_EVENT_MANAGER, NULL, 1);
}
#endif

long sys_workq_kernreturn(int options, void* item, int affinity, int prio)
{
#ifndef VARIANT_DYLD
	struct wq_kevent_data* wq_event = NULL;
	
	// __simple_printf("workq_kernreturn: 0x%x, %p, 0x%x, 0x%x\n", options, item, affinity, prio);

	// item is only used with WQOPS_QUEUE_ADD
	switch (options)
	{
		case WQOPS_THREAD_WORKLOOP_RETURN: // x86Code: same hand-back as kevent threads
		case WQOPS_THREAD_KEVENT_RETURN:
		{
			struct kevent_qos_s* keventlist = item;
			int nkevents = affinity;
			
			// __simple_printf("kevent return, obj=%p, nkevents=%d\n", wq_event, nkevents);

			struct wq_kevent_data* returning = wq_event_inflight_take(keventlist);
			if (returning == NULL)
			{
				returning = wq_event_pending;
				wq_event_pending = NULL;
			}

			if (returning != NULL)
			{
				if (nkevents > 0 && returning->events != keventlist)
					memmove(returning->events, keventlist, nkevents * sizeof(struct kevent_qos_s));
				returning->nevents = nkevents;
				if (returning->returned != NULL)
					returning->returned(returning);
				else
					sem_up(&returning->sem);
			}
			else
				__simple_printf("wq_event is NULL, something is going to get stuck forever\n");
		}
		case WQOPS_THREAD_RETURN:
		{
			// Signalizes that the thread has completed its job
			// and can be either recycled or terminated

			int thread_self;
			struct parked_thread me;
			dthread_t dthread;
			bool terminating = false;

			// x86Code: the run's flags (wq_spawn's) say which limits it counted against
			const uintptr_t run_flags = (uintptr_t) _pthread_getspecific_direct(__PTK_DARLING_WQ_FLAGS);
			// x86Code: an event manager thread's run ends here
			if (run_flags & WQ_FLAG_THREAD_EVENT_MANAGER)
			{
				_pthread_setspecific_direct(__PTK_DARLING_WQ_FLAGS, 0);
				wq_mgr_release();
			}

			os_unfair_lock_lock(&workq_parked_lock);

			// Semaphore locked state (wait for wakeup)
			me.sem = 0;

			// extract initial flags
			// (in case we only get created and used once and then terminate; `_pthread_wqthread` requires a valid `flags` argument)
			dthread = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_SELF);
			prio = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_QOS_CLASS);
			// doesn't extract `WQ_FLAG_THREAD_KEVENT` if we had it set, but that shouldn't matter
			// like i said before, the only case where we actually need these flags to be set here is when the thread is going to die immediately after creation
			me.flags = extract_wq_flags(prio);

			// Enqueue for future WQOPS_QUEUE_REQTHREADS
			TAILQ_INSERT_HEAD(&workq_parked_head, &me, entries);

			// Decrease the amount of running threads
			sem_up(&workq_sem);
			if (wq_flags_constrained(run_flags))
				sem_up(&workq_constrained_sem);

			os_unfair_lock_unlock(&workq_parked_lock);
			if (wq_flags_constrained(run_flags))
				wq_cpend_drain();

			// Wait until someone calls WQOPS_QUEUE_REQTHREADS
			// and wakes us up
			// (x86Code note: keep the idle timeout. Each reuse leaks a stack frame cycle,
			// see FINDINGS; exiting idle threads is what keeps that bounded.)
			if (!sem_down(&me.sem, 15))
			{
				// Make sure we haven't just been woken up before locking the queue
				// and remove us from the queue if not.
				os_unfair_lock_lock(&workq_parked_lock);
	
				if (me.sem > 0)
				{
					os_unfair_lock_unlock(&workq_parked_lock);
					goto wakeup;
				}

				TAILQ_REMOVE(&workq_parked_head, &me, entries);

				os_unfair_lock_unlock(&workq_parked_lock);

				terminating = true;

				// resume the thread; it'll call `_pthread_wqthread_exit` and kill itself
				goto resume_thread;
			}

wakeup: // we actually want to go back into the thread to do work
			// __simple_printf("Thread %d woken up, prio=%d\n", thread_self, me.flags & WQ_FLAG_THREAD_PRIOMASK);

			if (me.event)
				wq_event_pending = me.event;

resume_thread: // we want the thread to resume, but it might be just to die
			// reset stack and call entry point again with WQ_FLAG_THREAD_REUSE
			thread_self = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_MACH_THREAD_SELF);
			dthread = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_SELF);

			// x86Code: re-enter on the thread's entry stack (not this deep one)
			wqueue_entry_point_asm_jump_entry_stack(dthread, thread_self, dthread->stackbottom, 
				(!terminating && me.event) ? me.event->events : NULL, 
				me.flags | WQ_FLAG_THREAD_REUSE,
				terminating ? WORKQ_EXIT_THREAD_NKEVENT : (me.event ? me.event->nevents : 0)
			);
			
			__builtin_unreachable();

			return 0;
		}
		case WQOPS_SET_EVENT_MANAGER_PRIORITY:
		case WQOPS_QUEUE_NEWSPISUPP:
			return 0;
		case WQOPS_QUEUE_REQTHREAD_FOR_KEVENT:
		{
			wq_event = (struct wq_kevent_data*) item;
			affinity = 1;
			wq_event_inflight_add(wq_event);
		}
		case WQOPS_QUEUE_REQTHREADS2: // with prop bucket
		case WQOPS_QUEUE_REQTHREADS:
		{
			// affinity contains thread count

			int i, flags = extract_wq_flags(prio);

			// x86Code: REQTHREADS2 asks for cooperative pool threads (XNU's workq_reqthreads(..., cooperative =
			// true)): their upcall carries WQ_FLAG_THREAD_COOPERATIVE, so libpthread hands libdispatch a priority
			// with _PTHREAD_PRIORITY_COOPERATIVE_FLAG and the worker drains the cooperative root queue. Without
			// it the worker drained the plain root queue of that QoS, and work on the cooperative queues (every
			// Swift concurrency job on the global executor: Task.detached, async let, continuations resumed off
			// the main actor) never ran: WebKit's BrowserEngineKit process launches never completed.
			if (options == WQOPS_QUEUE_REQTHREADS2 && wq_event == NULL)
				flags = (flags & ~WQ_FLAG_THREAD_OVERCOMMIT) | WQ_FLAG_THREAD_COOPERATIVE;

			if (wq_event != NULL)
				flags |= WQ_FLAG_THREAD_KEVENT;
			if (wq_event != NULL && wq_event->workloop)
				flags |= WQ_FLAG_THREAD_WORKLOOP;
			
			// __simple_printf("Thread requested with prio %d\n", prio & WQ_FLAG_THREAD_PRIOMASK);

			// x86Code: one event manager thread at a time (as XNU)
			if ((flags & WQ_FLAG_THREAD_EVENT_MANAGER) && !wq_mgr_claim(wq_event))
				return 0;
			wq_spawn(flags, wq_event, affinity);
			return 0;
		}
		case WQOPS_SETUP_DISPATCH: {
			// TODO: actually do something with the info passed in
			// XNU just tacks it onto the process its called for and uses it later when someone asks for it

			/*
			struct workq_dispatch_config cfg = {0};

			// `affinity` contains the size of the config structure passed in
			memcpy(&cfg, item, (affinity < sizeof(struct workq_dispatch_config)) ? affinity : sizeof(struct workq_dispatch_config));
			*/

			return 0;
		} break;
		default:
			return -ENOTSUP;
	}
#else
	return -ENOSYS;
#endif
}

// x86Code: a counting semaphore that cannot lose a post. The old one stored -1 after
// decrementing (and 1 after incrementing), so a post that landed between a waiter's
// decrement and its store was overwritten and the waiter slept on. A parked workqueue
// thread then missed its WQOPS_QUEUE_REQTHREADS wakeup: the request was dropped and the
// queue it was for (e.g. launchd_sim's after "uncorking domain") ran only when some later
// event poked the workqueue again. It also took EINTR/EAGAIN from the futex as a post or
// a timeout. Now the value is never negative, waiters sleep while it is 0, and only
// ETIMEDOUT ends a wait without taking a post.
int sem_down(int* sem, int timeout)
{
	struct timespec ts = { timeout, 0 };

	for (;;)
	{
		int v = __atomic_load_n(sem, __ATOMIC_ACQUIRE);
		while (v > 0)
		{
			if (__atomic_compare_exchange_n(sem, &v, v - 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
				return 1;
		}

		int r = __linux_futex_reterr(sem, FUTEX_WAIT, v, (timeout != -1) ? &ts : NULL, 0, 0);
		if (r == -ETIMEDOUT)
		{
			v = __atomic_load_n(sem, __ATOMIC_ACQUIRE);
			while (v > 0)
			{
				if (__atomic_compare_exchange_n(sem, &v, v - 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
					return 1;
			}
			return 0;
		}
	}
}

void sem_up(int* sem)
{
	__atomic_add_fetch(sem, 1, __ATOMIC_RELEASE);
	__linux_futex_reterr(sem, FUTEX_WAKE, 1, NULL, 0, 0);
}

#define __PTHREAD_PRIORITY_CBIT_USER_INTERACTIVE 0x20
#define __PTHREAD_PRIORITY_CBIT_USER_INITIATED 0x10
#define __PTHREAD_PRIORITY_CBIT_DEFAULT 0x8
#define __PTHREAD_PRIORITY_CBIT_UTILITY 0x4
#define __PTHREAD_PRIORITY_CBIT_BACKGROUND 0x2
#define __PTHREAD_PRIORITY_CBIT_MAINTENANCE 0x1
#define __PTHREAD_PRIORITY_CBIT_UNSPECIFIED 0x0

#define QOS_CLASS_USER_INTERACTIVE 0x21
#define QOS_CLASS_USER_INITIATED 0x19
#define QOS_CLASS_DEFAULT 0x15
#define QOS_CLASS_UTILITY 0x11
#define QOS_CLASS_BACKGROUND 0x09
#define QOS_CLASS_MAINTENANCE 0x05
#define QOS_CLASS_UNSPECIFIED 0x0

static int priority_to_class(int prio)
{
	int dec_prio = (prio & 0xff00) >> 8;
	switch (dec_prio)
	{
		case __PTHREAD_PRIORITY_CBIT_USER_INTERACTIVE:
			return __PTHREAD_PRIORITY_CBIT_MAINTENANCE;
		case __PTHREAD_PRIORITY_CBIT_USER_INITIATED:
			return QOS_CLASS_USER_INITIATED;
		case __PTHREAD_PRIORITY_CBIT_DEFAULT:
			return QOS_CLASS_DEFAULT;
		case __PTHREAD_PRIORITY_CBIT_UTILITY:
			return QOS_CLASS_UTILITY;
		case __PTHREAD_PRIORITY_CBIT_BACKGROUND:
			return QOS_CLASS_BACKGROUND;
		case __PTHREAD_PRIORITY_CBIT_MAINTENANCE:
			return QOS_CLASS_MAINTENANCE;
		default:
			return QOS_CLASS_UNSPECIFIED;
	}
}
