#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_qos.h>

#include <stddef.h>
#include <sys/errno.h>
#include <sys/fcntl.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kqueue.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/workq_kernreturn.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent64.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

static int default_kq = -1;

extern void* memmove(void* dst, const void* src, __SIZE_TYPE__ n);

static void kevent_qos_to_64(const struct kevent_qos_s *ev, struct kevent64_s* ev64);
static void kevent_64_to_qos(const struct kevent64_s* ev64, struct kevent_qos_s *ev);

#ifndef VARIANT_DYLD
#include <libsimple/lock.h>
#include <pthread/tsd_private.h>

extern bool darling_foreign_libsystem(void);
extern void* darling_foreign_hook(const char* name);

static long kevent_qos_workq_async(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents, unsigned int flags);
#endif

// x86Code: NOTE_WL_SYNC_IPC knotes (dispatch's sync IPC handoff) only lend the waiter's
// priority to the servicer of a Mach port; there is no priority inheritance here, so they
// are accepted and ignored (failing them makes libdispatch crash)
static int is_sync_ipc(const struct kevent_qos_s* ch)
{
	return ch->filter == EVFILT_WORKLOOP && (ch->fflags & NOTE_WL_SYNC_IPC);
}

static int drop_sync_ipc(const struct kevent_qos_s* changelist, int nchanges, struct kevent_qos_s* out)
{
	int n = 0;
	for (int i = 0; i < nchanges; i++)
		if (!is_sync_ipc(&changelist[i]))
			out[n++] = changelist[i];
	return n;
}

long sys_kevent_qos(int	kq, const struct kevent_qos_s *changelist, int nchanges,
			struct	kevent_qos_s *eventlist, int nevents,
			void* data_out, unsigned long* data_available, unsigned int flags)
{
	int rv;
	struct kevent64_s* changelist64 = NULL;
	struct kevent64_s* eventlist64 = NULL;
	struct wq_kevent_data wq_kevent;
	struct timespec polling_timeout = {};

	if ((kq == -1) != !!(flags & KEVENT_FLAG_WORKQ))
		return -EINVAL;

	if (changelist != NULL && nchanges > 0)
	{
		struct kevent_qos_s* kept = (struct kevent_qos_s*) __builtin_alloca(nchanges * sizeof(*kept));
		nchanges = drop_sync_ipc(changelist, nchanges, kept);
		changelist = kept;
	}

	if (default_kq == -1)
	{
		default_kq = sys_kqueue();
		sys_fcntl(default_kq, F_SETFD, FD_CLOEXEC);
	}

#ifndef VARIANT_DYLD
	if ((flags & KEVENT_FLAG_WORKQ) && darling_foreign_libsystem())
		return kevent_qos_workq_async(changelist, nchanges, eventlist, nevents, flags);
#endif

	if (changelist != NULL && nchanges > 0)
	{
		int i;

		changelist64 = (struct kevent64_s*) __builtin_alloca(nchanges * sizeof(struct kevent64_s));
		for (i = 0; i < nchanges; i++)
			kevent_qos_to_64(&changelist[i], &changelist64[i]);
	}
	if (eventlist != NULL && nevents > 0)
		eventlist64 = (struct kevent64_s*) __builtin_alloca(nevents * sizeof(struct kevent64_s));
	if (nevents == 0 && (flags & KEVENT_FLAG_WORKQ))
	{
		eventlist = (struct kevent_qos_s*) __builtin_alloca(nevents * sizeof(struct kevent_qos_s));
		nevents = 1;
		eventlist64 = (struct kevent64_s*) __builtin_alloca(nevents * sizeof(struct kevent64_s));
	}

	rv = sys_kevent64(kq, changelist64, nchanges, eventlist64, nevents, flags, (flags & KEVENT_FLAG_IMMEDIATE) ? &polling_timeout : NULL);

	if (rv > 0)
	{
		int i;

		for (i = 0; i < rv; i++)
			kevent_64_to_qos(&eventlist64[i], &eventlist[i]);
	}

	if (flags & KEVENT_FLAG_WORKQ)
	{
		// Pass to workqueue and wait
		wq_kevent.sem = 0;
		wq_kevent.events = eventlist;
		wq_kevent.nevents = rv;

		sys_workq_kernreturn(WQOPS_QUEUE_REQTHREAD_FOR_KEVENT, &wq_kevent, 1, 0);
		
		// __simple_printf("waiting for workq processing\n");
		sem_down(&wq_kevent.sem, -1);

		rv = wq_kevent.nevents;
		memmove(eventlist, wq_kevent.events, rv * sizeof(struct kevent_qos_s));
		// __simple_printf("workq done processing, returning %d to caller\n", rv);
	}
	
	return rv;
}


void kevent_qos_to_64(const struct kevent_qos_s *ev, struct kevent64_s* ev64)
{
	ev64->ident = ev->ident;
	ev64->filter = ev->filter;
	ev64->flags = ev->flags;
	ev64->fflags = ev->fflags;
	ev64->data = ev->data;
	ev64->udata = ev->udata;
	ev64->ext[0] = ev->ext[0];
	ev64->ext[1] = ev->ext[1];
}

void kevent_64_to_qos(const struct kevent64_s* ev64, struct kevent_qos_s *ev)
{
	ev->ident = ev64->ident;
	ev->filter = ev64->filter;
	ev->flags = ev64->flags;
	ev->qos = 0;
	ev->fflags = ev64->fflags;
	ev->data = ev64->data;
	ev->udata = ev64->udata;
	ev->ext[0] = ev64->ext[0];
	ev->ext[1] = ev64->ext[1];
	ev->ext[2] = ev->ext[3] = 0;
}

#ifndef VARIANT_DYLD
/*
 * XNU-style kevent workqueue for foreign libSystems (the iOS simulator's
 * libdispatch requires WORKQ_FEATURE_KEVENT):
 *
 * - KEVENT_FLAG_WORKQ calls only register/modify knotes on the process's
 *   workq kqueue and return immediately (with KEVENT_FLAG_ERROR_EVENTS, only
 *   the errors are returned).
 * - A manager thread waits on that kqueue and hands each batch of fired
 *   events to a workqueue thread (WQ_FLAG_THREAD_KEVENT). The changes that
 *   thread passes back with WQOPS_THREAD_KEVENT_RETURN (re-arming etc.) are
 *   applied before waiting again.
 *
 * Batches run in parallel, as XNU runs them (x86Code, Input 3: see wq_deliver).
 */

#define WQ_KEVENT_BATCH 16
#define WQ_KEVENT_RETURN_MAX 64
// pthread priority for QOS_CLASS_DEFAULT (thread QoS 4), unspecified relative priority
#define WQ_KEVENT_PRIORITY 0x8ff
#define PTHREAD_PRIORITY_EVENT_MANAGER_FLAG 0x02000000
#define WQ_QOS_TABLE_SIZE 1024

#define WQDBG(...) // __simple_printf(__VA_ARGS__)

static libsimple_once_t wq_manager_once = LIBSIMPLE_ONCE_INITIALIZER;

static void wl_post_event(uint64_t id, const struct kevent_qos_s* ev);

// kevent64 has no qos field, so remember each knote's qos (it decides
// whether an event goes to the event manager thread) by (ident, filter, udata)
struct wq_knote_qos
{
	uint64_t ident;
	uint64_t udata;
	int16_t filter;
	bool used;
	uint32_t qos;
	// workloop the knote was registered on with kevent_id (0: the workq kqueue)
	uint64_t workloop;
};
static struct wq_knote_qos wq_qos_table[WQ_QOS_TABLE_SIZE];
static libsimple_lock_t wq_qos_lock = LIBSIMPLE_LOCK_INITIALIZER;
// x86Code: set once a knote could not be recorded; from then on liveness is unknown
static bool wq_qos_overflow;

static struct wq_knote_qos* wq_qos_find_locked(uint64_t ident, int16_t filter, uint64_t udata)
{
	struct wq_knote_qos* by_ident = NULL;
	int i;

	for (i = 0; i < WQ_QOS_TABLE_SIZE; i++)
	{
		struct wq_knote_qos* e = &wq_qos_table[i];
		if (!e->used || e->ident != ident || e->filter != filter)
			continue;
		if (e->udata == udata)
			return e;
		by_ident = e;
	}
	return by_ident;
}

static void wq_qos_record(const struct kevent_qos_s* ch, uint64_t workloop)
{
	struct wq_knote_qos* e;
	int i;

	libsimple_lock_lock(&wq_qos_lock);
	e = wq_qos_find_locked(ch->ident, ch->filter, ch->udata);
	if (e != NULL && e->udata != ch->udata)
		e = NULL;

	if (ch->flags & EV_DELETE)
	{
		// x86Code: see wq_apply_changes: only called once the delete took effect
		if (e != NULL)
			e->used = false;
	}
	else if (ch->flags & EV_ADD)
	{
		if (e == NULL)
		{
			for (i = 0; i < WQ_QOS_TABLE_SIZE && wq_qos_table[i].used; i++);
			if (i < WQ_QOS_TABLE_SIZE)
				e = &wq_qos_table[i];
			else
			{
				__simple_printf("kevent workq: qos table full\n");
				wq_qos_overflow = true;
			}
		}
		if (e != NULL)
		{
			e->ident = ch->ident;
			e->filter = ch->filter;
			e->udata = ch->udata;
			e->qos = ch->qos;
			if (!e->used || workloop != 0)
				e->workloop = workloop;
			e->used = true;
		}
	}
	else if (e != NULL && ch->qos != 0)
		e->qos = ch->qos;
	libsimple_lock_unlock(&wq_qos_lock);
}

/*
 * x86Code: is the knote an event was copied out for still registered? The manager thread
 * copies events out of libkqueue (for Mach ports that is when darlingserver hands over the
 * message, or a fake EV_VANISHED once the receive right is destroyed) and only then queues
 * them for a servicer. A knote deleted in between must not get the event: XNU drops a
 * deleted knote's activation with it. Delivered anyway, libdispatch merged it into a freed
 * unote ("API MISUSE: Resurrection of an object", backboardd) or into a mach channel it had
 * disconnected and whose port it had destroyed ("Unexpected EV_VANISHED", Spotlight): libxpc
 * cancels a connection (EV_DELETE succeeds), destroys the port, darlingserver reports it
 * vanished to the still-open kqchan, the manager reads that before the close is seen...
 * Called with wq_qos_lock held.
 */
static bool wq_knote_live_locked(const struct kevent_qos_s* ev)
{
	struct wq_knote_qos* e;

	if (wq_qos_overflow)
		return true;
	e = wq_qos_find_locked(ev->ident, ev->filter, ev->udata);
	if (e == NULL)
		return false;
	return !(ev->flags & EV_UDATA_SPECIFIC) || e->udata == ev->udata;
}

static bool wq_knote_live(const struct kevent_qos_s* ev)
{
	bool live;
	libsimple_lock_lock(&wq_qos_lock);
	live = wq_knote_live_locked(ev);
	libsimple_lock_unlock(&wq_qos_lock);
	return live;
}

static uint32_t wq_qos_lookup(const struct kevent_qos_s* ev, uint64_t* workloop)
{
	struct wq_knote_qos* e;
	uint32_t qos = 0;

	*workloop = 0;
	libsimple_lock_lock(&wq_qos_lock);
	e = wq_qos_find_locked(ev->ident, ev->filter, ev->udata);
	if (e != NULL)
	{
		qos = e->qos;
		*workloop = e->workloop;
	}
	libsimple_lock_unlock(&wq_qos_lock);
	return qos;
}

// Apply a changelist to the workq kqueue; with `receipts`, errors come back in it
static int wq_apply_changes(const struct kevent_qos_s* changelist, int nchanges, struct kevent64_s* receipts, uint64_t workloop)
{
	struct kevent64_s* ch64 = __builtin_alloca(nchanges * sizeof(struct kevent64_s));
	struct kevent64_s* rc = receipts ? receipts : __builtin_alloca(nchanges * sizeof(struct kevent64_s));
	struct timespec zero = {};
	int i, nr;

	for (i = 0; i < nchanges; i++)
	{
		if (!(changelist[i].flags & EV_DELETE))
			wq_qos_record(&changelist[i], workloop);
		kevent_qos_to_64(&changelist[i], &ch64[i]);
		ch64[i].flags |= EV_RECEIPT;
	}
	nr = sys_kevent64(default_kq, ch64, nchanges, rc, nchanges, 0, &zero);
	// x86Code: a knote stays live until its delete succeeds (or it is not there at all): a
	// deferred delete (EINPROGRESS) still has its in-flight event to deliver
	for (i = 0; i < nchanges; i++)
	{
		if (!(changelist[i].flags & EV_DELETE) || nr < 0)
			continue;
		if (i < nr && (rc[i].flags & EV_ERROR) && rc[i].data != 0 && rc[i].data != ENOENT)
			continue;
		wq_qos_record(&changelist[i], workloop);
	}
	// callers without receipts get no results, as before
	return receipts == NULL && nr > 0 ? 0 : nr;
}

// x86Code (Input 3): batches run asynchronously. The manager handed a batch to a workqueue thread and waited for it
// to return before it looked at the kqueue again, so while one kevent thread's handler blocked, no other event of the
// process was delivered. A handler that blocks on something only another event brings deadlocked the process: an
// iPad SpringBoard's kevent thread waited in a dispatch_sync on a workloop whose servicer was rendering a killed
// app's switcher snapshot, which waited in -[MTLSimCommandBuffer waitUntilCompleted] for metalhostd's "completed"
// message; that message (and every later one: touches, launches, SBS calls) sat queued on its port, its kqchan
// notification sent but never read. XNU requests a thread per batch and never waits for one. Now each batch gets
// a slot and the changes come back on the returning thread (wq_batch_returned), as workloop batches do; knotes
// stay quiet meanwhile as before (EV_DISPATCH / EV_ONESHOT / EV_CLEAR, the event manager runs one at a time:
// wq_mgr_claim). With every slot in use the manager waits for one as it waited for each batch before.
#define WQ_BATCH_SLOTS 48
struct wq_batch_slot
{
	struct wq_kevent_data data;
	struct kevent_qos_s events[WQ_KEVENT_RETURN_MAX];
	bool used;
};
static struct wq_batch_slot wq_batch_slots[WQ_BATCH_SLOTS];
static libsimple_lock_t wq_batch_lock = LIBSIMPLE_LOCK_INITIALIZER;
static int wq_batch_free_sem = WQ_BATCH_SLOTS;

static void wq_batch_returned(struct wq_kevent_data* data)
{
	struct wq_batch_slot* slot = (struct wq_batch_slot*) ((char*) data - offsetof(struct wq_batch_slot, data));
	int n = data->nevents;
	WQDBG("kevent thread returned %d changes\n", n);
	if (n > WQ_KEVENT_RETURN_MAX)
	{
		__simple_printf("kevent workq: %d returned changes, only %d applied\n", n, WQ_KEVENT_RETURN_MAX);
		n = WQ_KEVENT_RETURN_MAX;
	}
	if (n > 0)
		wq_apply_changes(slot->events, n, NULL, 0);
	libsimple_lock_lock(&wq_batch_lock);
	slot->used = false;
	libsimple_lock_unlock(&wq_batch_lock);
	sem_up(&wq_batch_free_sem);
}

// Hand one batch to a workqueue thread; its changes are applied when it returns
static void wq_deliver(struct kevent_qos_s* events, int n, int priority)
{
	struct wq_batch_slot* slot = NULL;
	int i, m = 0;

	sem_down(&wq_batch_free_sem, -1);
	libsimple_lock_lock(&wq_batch_lock);
	for (i = 0; i < WQ_BATCH_SLOTS; i++)
	{
		if (!wq_batch_slots[i].used)
		{
			slot = &wq_batch_slots[i];
			slot->used = true;
			break;
		}
	}
	libsimple_lock_unlock(&wq_batch_lock);

	for (i = 0; i < n; i++)
		if (wq_knote_live(&events[i])) // x86Code: deleted meanwhile (see wq_knote_live_locked)
			slot->events[m++] = events[i];
	if (m == 0)
	{
		libsimple_lock_lock(&wq_batch_lock);
		slot->used = false;
		libsimple_lock_unlock(&wq_batch_lock);
		sem_up(&wq_batch_free_sem);
		return;
	}

	slot->data = (struct wq_kevent_data) {
		.events = slot->events,
		.nevents = m,
		.sem = 0,
		.capacity = WQ_KEVENT_RETURN_MAX,
		.returned = wq_batch_returned,
	};
	sys_workq_kernreturn(WQOPS_QUEUE_REQTHREAD_FOR_KEVENT, &slot->data, 1, priority);
}

extern void sigexc_setup2(void);
extern long sys_open(const char* filename, int flags, unsigned int mode);
extern long sys_getpid(void);
extern void __simple_fprintf(int fd, const char* format, ...);

// x86Code (debug): if /private/var/tmp/x86code-wqdbg exists, the manager logs the events it receives to
// /private/tmp/x86code-wqmgr.<pid>.log: the first 300, then one in 20000 (finds a knote that fires nonstop)
static int wq_dbg_fd = -2;
static unsigned long wq_dbg_n;
static void wq_dbg_event(const struct kevent64_s* ev, bool live, uint32_t qos, uint64_t workloop)
{
	if (wq_dbg_fd == -2)
	{
		int probe = sys_open("/private/var/tmp/x86code-wqdbg", O_RDONLY, 0);
		wq_dbg_fd = -1;
		if (probe >= 0)
		{
			char path[64];
			close_internal(probe);
			__simple_sprintf(path, "/private/tmp/x86code-wqmgr.%d.log", (int) sys_getpid());
			wq_dbg_fd = sys_open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
		}
	}
	if (wq_dbg_fd < 0)
		return;
	wq_dbg_n++;
	if (wq_dbg_n > 300 && wq_dbg_n % 20000)
		return;
	__simple_fprintf(wq_dbg_fd, "#%lu ident=%llx filter=%d flags=0x%x fflags=0x%x data=%lld udata=%llx ext0=%llx ext1=%llx live=%d qos=0x%x wl=%llx\n",
		wq_dbg_n, (unsigned long long) ev->ident, ev->filter, ev->flags, ev->fflags, (long long) ev->data,
		(unsigned long long) ev->udata, (unsigned long long) ev->ext[0], (unsigned long long) ev->ext[1], live, qos,
		(unsigned long long) workloop);
}

static void* wq_kevent_manager(void* unused)
{
	struct kevent64_s ev64[WQ_KEVENT_BATCH];
	struct kevent_qos_s mgr[WQ_KEVENT_BATCH], work[WQ_KEVENT_BATCH];

	// This thread is created from inside a syscall and inherits its signal mask.
	// darlingserver interrupts a thread with SIGNAL_S2C when it needs the process to
	// act for it (e.g. map out-of-line data of a Mach message this thread receives
	// through a kqueue); blocked, that deadlocks the server and the process.
	sigexc_setup2();

	for (;;)
	{
		int i, nmgr = 0, nwork = 0;
		int n = sys_kevent64(default_kq, NULL, 0, ev64, WQ_KEVENT_BATCH, 0, NULL);
		if (n <= 0)
		{
			if (n < 0 && n != -EINTR)
				__simple_printf("wq_kevent_manager: kevent64 failed: %d\n", n);
			continue;
		}

		for (i = 0; i < n; i++)
		{
			struct kevent_qos_s ev;
			uint64_t workloop;
			kevent_64_to_qos(&ev64[i], &ev);
			// x86Code: drop events of knotes deleted since the copyout (see wq_knote_live_locked)
			if (!wq_knote_live(&ev))
			{
				wq_dbg_event(&ev64[i], false, 0, 0);
				continue;
			}
			ev.qos = wq_qos_lookup(&ev, &workloop);
			wq_dbg_event(&ev64[i], true, ev.qos, workloop);
			if (workloop != 0)
			{
				wl_post_event(workloop, &ev);
				continue;
			}
			WQDBG("manager: event ident=%llu filter=%d flags=0x%x qos=0x%x\n", (unsigned long long) ev.ident, ev.filter, ev.flags, ev.qos);
			if (ev.qos & PTHREAD_PRIORITY_EVENT_MANAGER_FLAG)
				mgr[nmgr++] = ev;
			else
				work[nwork++] = ev;
		}

		if (nmgr > 0)
			wq_deliver(mgr, nmgr, PTHREAD_PRIORITY_EVENT_MANAGER_FLAG);
		if (nwork > 0)
			wq_deliver(work, nwork, WQ_KEVENT_PRIORITY);
	}
	return NULL;
}

static void wq_start_manager(void* context)
{
	int (*create)(void** thread, const void* attr, void* (*start)(void*), void* arg)
		= darling_foreign_hook("pthread_create");
	void* thread;

	if (create == NULL || create(&thread, NULL, wq_kevent_manager, NULL) != 0)
		__simple_printf("kevent workq: failed to start the manager thread\n");
}

static long kevent_qos_workq_async(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents, unsigned int flags)
{
	struct timespec zero = {};
	int i, nout = 0;

	libsimple_once(&wq_manager_once, wq_start_manager, NULL);
	WQDBG("workq kevent: nchanges=%d nevents=%d flags=0x%x\n", nchanges, nevents, flags);

	if (changelist != NULL && nchanges > 0)
	{
		// EV_RECEIPT makes every change produce a result, so no ready event is consumed here
		struct kevent64_s* rc64 = __builtin_alloca(nchanges * sizeof(struct kevent64_s));
		int nr = wq_apply_changes(changelist, nchanges, rc64, 0);

		if (nr < 0)
			return nr;

		for (i = 0; i < nr; i++)
		{
			if (!(rc64[i].flags & EV_ERROR) || rc64[i].data == 0)
				continue;
			if (eventlist == NULL || nout >= nevents)
				return -rc64[i].data;
			kevent_64_to_qos(&rc64[i], &eventlist[nout++]);
		}
	}

	// Only errors were requested, or the thread is about to park: events go to the manager
	if (flags & (KEVENT_FLAG_ERROR_EVENTS | KEVENT_FLAG_PARKING))
		return nout;

	if (eventlist != NULL && nevents > nout)
	{
		struct kevent64_s* ev64 = __builtin_alloca((nevents - nout) * sizeof(struct kevent64_s));
		int n = sys_kevent64(default_kq, NULL, 0, ev64, nevents - nout, 0, &zero);

		for (i = 0; i < n; i++)
			kevent_64_to_qos(&ev64[i], &eventlist[nout++]);
	}
	return nout;
}
#endif

extern long sys_open(const char* filename, int flags, unsigned int mode);
extern void __simple_fprintf(int fd, const char* format, ...);

#ifndef VARIANT_DYLD
/*
 * x86Code: workloop kqueues (kevent_id, KEVENT_FLAG_WORKLOOP) for foreign
 * libSystems. libdispatch drives every serial queue hierarchy through one.
 *
 * Emulated subset, following XNU's kern_event.c:
 * - NOTE_WL_THREAD_REQUEST knotes (with debounce): while one exists, or events
 *   are queued, and no thread is servicing the workloop, a workqueue thread is
 *   started with WQ_FLAG_THREAD_WORKLOOP. Its batch is the thread request event
 *   followed by the queued events; the workloop id sits just before the batch.
 * - Other filters are registered on the workq kqueue and tagged with their
 *   workloop; the manager thread queues their events on it.
 * - Sync knotes (dispatch_sync): NOTE_WL_SYNC_WAIT blocks until the knote is
 *   woken by NOTE_WL_SYNC_WAKE (which with EV_ADD may create it already woken)
 *   or deleted; the knote lives until EV_DELETE. No priority inheritance or
 *   ownership tracking.
 * A servicer that calls kevent_id with an event list receives queued events.
 */
#define WL_MAX 256
#define WL_EVENTS 64
#define WL_WAITERS 64

struct wl_batch
{
	uint64_t id; // libpthread reads keventlist[-1]
	struct kevent_qos_s events[WL_EVENTS + 1];
};

struct workloop
{
	uint64_t id;
	bool used;
	bool servicing;
	bool has_request;
	// x86Code: as in XNU the thread request knote is EV_CLEAR: delivering it to a
	// servicer consumes it until it is touched again (EV_ADD/EV_ENABLE). It was
	// redelivered on every bind, waking servicers for a workloop nobody enqueued.
	bool request_active;
	// x86Code: kqwl_owner: port name (low 2 bits masked) of the thread that owns the
	// workloop (uncontended dispatch_sync), learnt from NOTE_WL_DISCOVER_OWNER and
	// cleared by NOTE_WL_END_OWNERSHIP from that thread. No servicer runs while set.
	uint32_t owner;
	struct kevent_qos_s request;
	int npending;
	struct kevent_qos_s pending[WL_EVENTS];
	struct wq_kevent_data data;
	struct wl_batch batch;
};

struct wl_waiter
{
	uint64_t workloop, ident;
	bool used, woken;
	bool blocked, deleted; // a thread waits on it; EV_DELETE came meanwhile
	int sem;
};

static struct workloop wl_table[WL_MAX];
static struct wl_waiter wl_waiters[WL_WAITERS];
static libsimple_lock_t wl_lock = LIBSIMPLE_LOCK_INITIALIZER;
static int wl_log_fd = -1;

extern long sys_getpid(void);

// One log per process: /private/tmp/x86code-workloop.<pid>.log
#define WLLOG(...) do { \
		if (wl_log_fd < 0) { \
			char wl_log_path[64]; \
			__simple_sprintf(wl_log_path, "/private/tmp/x86code-workloop.%d.log", (int) sys_getpid()); \
			wl_log_fd = sys_open(wl_log_path, O_WRONLY | O_CREAT | O_APPEND, 0644); \
		} \
		__simple_fprintf(wl_log_fd, __VA_ARGS__); \
	} while (0)

static void wl_returned(struct wq_kevent_data* data);

// mach_port_name_t of a thread as libdispatch stores it in dq_state, low 2 bits masked
static uint32_t wl_port_mask(uint64_t name)
{
	return (uint32_t) name & ~0x3u;
}

static uint32_t wl_self(void)
{
	return wl_port_mask((uintptr_t) _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_MACH_THREAD_SELF));
}

#define WLTRACE(...) // WLLOG(__VA_ARGS__)

static struct workloop* wl_get_locked(uint64_t id)
{
	struct workloop* free_slot = NULL;
	int i;

	// x86Code: workloops were never freed, so a process that made more than WL_MAX of
	// them over its life (backboardd: an XPC connection, and so a workloop, per Metal
	// reconnect) got ENOMEM from kevent_id, and libdispatch crashed in
	// _dispatch_event_loop_poke ("Unexpected error from kernel"). An idle entry (not
	// serviced, no thread request, no queued events) is the same as no entry, so its
	// slot can be taken by another id; the next use of its own id starts it afresh.
	for (i = 0; i < WL_MAX; i++)
	{
		struct workloop* wl = &wl_table[i];
		if (wl->used && wl->id == id)
			return wl;
		if (free_slot == NULL && (!wl->used || (!wl->servicing && !wl->has_request && wl->npending == 0 && !wl->owner)))
			free_slot = wl;
	}
	if (free_slot == NULL)
	{
		WLLOG("workloop table full (id 0x%llx)\n", (unsigned long long) id);
		return NULL;
	}
	free_slot->id = id;
	free_slot->used = true;
	free_slot->servicing = false;
	free_slot->has_request = false;
	free_slot->request_active = false;
	free_slot->owner = 0;
	free_slot->npending = 0;
	return free_slot;
}

// Called with wl_lock held. Returns true if the caller must request the thread
// (after unlocking) with wl_request_thread.
static bool wl_bind_locked(struct workloop* wl)
{
	int n = 0;
	bool deliver_request = wl->has_request && wl->request_active;

	// x86Code: no servicer while a thread owns the workloop (XNU kqworkloop_wakeup)
	if (wl->servicing || wl->owner != 0 || (!deliver_request && wl->npending == 0))
		return false;

	if (deliver_request)
	{
		wl->request_active = false;
		struct kevent_qos_s* ev = &wl->batch.events[n++];
		*ev = wl->request;
		ev->flags &= ~(EV_ADD | EV_DELETE | EV_ERROR | EV_RECEIPT);
		ev->data = 0;
	}
	memmove(&wl->batch.events[n], wl->pending, wl->npending * sizeof(struct kevent_qos_s));
	n += wl->npending;
	wl->npending = 0;

	wl->batch.id = wl->id;
	wl->data = (struct wq_kevent_data) {
		.events = wl->batch.events,
		.nevents = n,
		.workloop = 1,
		.capacity = WL_EVENTS + 1,
		.returned = wl_returned,
	};
	wl->servicing = true;
	WLTRACE("bind 0x%llx: %d events (request %d)\n", (unsigned long long) wl->id, n, deliver_request);
	return true;
}

static void wl_request_thread(struct workloop* wl)
{
	uint32_t prio = wl->has_request && wl->request.qos != 0 ? wl->request.qos : WQ_KEVENT_PRIORITY;
	sys_workq_kernreturn(WQOPS_QUEUE_REQTHREAD_FOR_KEVENT, &wl->data, 1, prio & ~PTHREAD_PRIORITY_EVENT_MANAGER_FLAG);
}

// Drop queued events for a knote that was deleted or disabled
static void wl_purge_locked(struct workloop* wl, const struct kevent_qos_s* ch)
{
	int i, n = 0;
	for (i = 0; i < wl->npending; i++)
	{
		if (wl->pending[i].ident == ch->ident && wl->pending[i].filter == ch->filter)
			continue;
		wl->pending[n++] = wl->pending[i];
	}
	wl->npending = n;
}

static void wl_post_event(uint64_t id, const struct kevent_qos_s* ev)
{
	struct workloop* wl;
	bool request = false;

	WLTRACE("event 0x%llx: ident=0x%llx filter=%d flags=0x%x fflags=0x%x data=0x%llx ext=%llx,%llx\n",
		(unsigned long long) id, (unsigned long long) ev->ident, ev->filter, ev->flags, ev->fflags,
		(unsigned long long) ev->data, (unsigned long long) ev->ext[0], (unsigned long long) ev->ext[1]);
	libsimple_lock_lock(&wl_lock);
	// x86Code: a delete recorded before this is skipped here; one recorded after purges it
	if (!wq_knote_live(ev))
	{
		libsimple_lock_unlock(&wl_lock);
		return;
	}
	wl = wl_get_locked(id);
	if (wl != NULL)
	{
		if (wl->npending < WL_EVENTS)
			wl->pending[wl->npending++] = *ev;
		else
			WLLOG("workloop 0x%llx: event queue full\n", (unsigned long long) id);
		request = wl_bind_locked(wl);
	}
	libsimple_lock_unlock(&wl_lock);

	if (request)
		wl_request_thread(wl);
}

// The servicing thread returned (WQOPS_THREAD_WORKLOOP_RETURN)
static void wl_returned(struct wq_kevent_data* data)
{
	struct workloop* wl = (struct workloop*) ((char*) data - offsetof(struct workloop, data));
	int n = data->nevents, nerr = 0;
	struct kevent_qos_s errors[WL_EVENTS];
	bool request;

	WLTRACE("return 0x%llx: %d changes\n", (unsigned long long) wl->id, n);
	// x86Code: XNU applies the changes a servicer returns (KEVENT_FLAG_PARKING) and hands
	// their errors back to it, e.g. an ESTALE "leave" that libdispatch then redrives. They
	// were dropped, and the first error also stopped the remaining changes.
	if (n > 0)
		nerr = sys_kevent_id(wl->id, data->events, n < WL_EVENTS ? n : WL_EVENTS, errors, WL_EVENTS, NULL, NULL,
			KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS);
	if (nerr < 0)
		nerr = 0;

	libsimple_lock_lock(&wl_lock);
	// the servicer is never the owner (XNU kqueue_threadreq_bind)
	if (wl->owner == wl_self())
		wl->owner = 0;
	if (nerr > 0)
	{
		if (nerr > WL_EVENTS - wl->npending)
			nerr = WL_EVENTS - wl->npending;
		memmove(&wl->pending[nerr], wl->pending, wl->npending * sizeof(struct kevent_qos_s));
		memmove(wl->pending, errors, nerr * sizeof(struct kevent_qos_s));
		wl->npending += nerr;
	}
	wl->servicing = false;
	request = wl_bind_locked(wl);
	libsimple_lock_unlock(&wl_lock);

	if (request)
		wl_request_thread(wl);
}

// Debounce: the change only applies if (*addr & mask) == (value & mask)
// x86Code: like filt_wlupdate, the loaded value goes back in ext[VALUE] (libdispatch redrives
// an ESTALE error from it), and ownership is discovered/ended here
static bool wl_stale(struct workloop* wl, struct kevent_qos_s* ch)
{
	const uint64_t* addr = (const uint64_t*) ch->ext[EV_EXTIDX_WL_ADDR];
	uint32_t new_owner = wl->owner;
	bool stale = false;

	if (addr != NULL)
	{
		uint64_t value = __atomic_load_n(addr, __ATOMIC_ACQUIRE);
		stale = ((value ^ ch->ext[EV_EXTIDX_WL_VALUE]) & ch->ext[EV_EXTIDX_WL_MASK]) != 0;
		ch->ext[EV_EXTIDX_WL_VALUE] = value;
		if (!stale && (ch->fflags & NOTE_WL_DISCOVER_OWNER) && wl_port_mask(value) != 0)
			new_owner = wl_port_mask(value);
	}
	if ((ch->fflags & NOTE_WL_END_OWNERSHIP) && new_owner == wl_self())
		new_owner = 0;
	if (new_owner != wl->owner)
		WLTRACE("  owner 0x%llx: 0x%x -> 0x%x\n", (unsigned long long) wl->id, wl->owner, new_owner);
	wl->owner = new_owner;
	return stale;
}

// Apply one EVFILT_WORKLOOP change; returns 0 or a (positive) errno
static int wl_change(uint64_t id, struct kevent_qos_s* ch)
{
	uint32_t cmd = ch->fflags & NOTE_WL_COMMANDS_MASK;
	struct workloop* wl;
	struct wl_waiter* waiter = NULL;
	bool request = false;
	int err = 0, i;

	libsimple_lock_lock(&wl_lock);
	wl = wl_get_locked(id);
	if (wl == NULL)
		err = ENOMEM;
	else if (wl_stale(wl, ch))
	{
		err = (ch->fflags & NOTE_WL_IGNORE_ESTALE) ? 0 : ESTALE;
		// ending ownership may let a pending thread request run
		request = wl_bind_locked(wl);
	}
	else if (cmd == NOTE_WL_THREAD_REQUEST)
	{
		if (ch->flags & (EV_DELETE | EV_DISABLE))
		{
			wl->has_request = false;
			wl->request_active = false;
			request = wl_bind_locked(wl);
		}
		else if ((ch->flags & EV_ADD) || wl->has_request)
		{
			uint32_t qos = wl->request.qos;
			wl->request = *ch;
			if (wl->has_request && !(ch->fflags & NOTE_WL_UPDATE_QOS) && !(ch->flags & EV_ADD))
				wl->request.qos = qos;
			wl->has_request = true;
			wl->request_active = true;
			request = wl_bind_locked(wl);
		}
		else
			err = ENOENT;
	}
	else if (cmd == NOTE_WL_SYNC_WAIT || cmd == NOTE_WL_SYNC_WAKE)
	{
		struct wl_waiter* w = NULL;
		for (i = 0; i < WL_WAITERS; i++)
		{
			if (wl_waiters[i].used && !wl_waiters[i].deleted && wl_waiters[i].workloop == id && wl_waiters[i].ident == ch->ident)
			{
				w = &wl_waiters[i];
				break;
			}
		}
		if (w == NULL && (ch->flags & EV_ADD) && !(ch->flags & EV_DELETE))
		{
			for (i = 0; i < WL_WAITERS && wl_waiters[i].used; i++);
			if (i < WL_WAITERS)
			{
				w = &wl_waiters[i];
				*w = (struct wl_waiter) { .workloop = id, .ident = ch->ident, .used = true };
			}
			else
				WLLOG("workloop: too many sync waiters\n");
		}

		if (w == NULL)
			err = (ch->flags & EV_ADD) ? ENOMEM : ENOENT;
		else if (ch->flags & EV_DELETE)
		{
			// a blocked waiter is released and frees the entry itself
			if (!w->woken)
			{
				w->woken = true;
				sem_up(&w->sem);
			}
			if (w->blocked)
				w->deleted = true;
			else
				w->used = false;
		}
		else if (cmd == NOTE_WL_SYNC_WAKE)
		{
			if (!w->woken)
			{
				w->woken = true;
				sem_up(&w->sem);
			}
		}
		else if (!w->woken)
		{
			waiter = w;
			w->blocked = true;
		}
		if (err == 0)
			request = wl_bind_locked(wl);
	}
	else if (cmd != 0)
	{
		WLLOG("workloop 0x%llx: unhandled fflags 0x%x flags 0x%x\n", (unsigned long long) id, ch->fflags, ch->flags);
		err = ENOTSUP;
	}
	libsimple_lock_unlock(&wl_lock);

	if (request)
		wl_request_thread(wl);
	if (waiter != NULL)
	{
		WLTRACE("  sync wait 0x%llx\n", (unsigned long long) ch->ident);
		while (!__atomic_load_n(&waiter->woken, __ATOMIC_ACQUIRE))
			sem_down(&waiter->sem, -1);
		libsimple_lock_lock(&wl_lock);
		waiter->blocked = false;
		if (waiter->deleted)
			waiter->used = false;
		libsimple_lock_unlock(&wl_lock);
	}
	return err;
}

long sys_kevent_id(unsigned long long id, const struct kevent_qos_s *changelist, int nchanges,
			struct kevent_qos_s *eventlist, int nevents,
			void* data_out, unsigned long* data_available, unsigned int flags)
{
	int i, nout = 0;

	if (!darling_foreign_libsystem())
		return -ENOSYS;
	libsimple_once(&wq_manager_once, wq_start_manager, NULL);
	WLTRACE("kevent_id 0x%llx: nchanges=%d nevents=%d flags=0x%x\n", id, nchanges, nevents, flags);

	for (i = 0; i < nchanges; i++)
	{
		struct kevent_qos_s chcopy = changelist[i];
		struct kevent_qos_s* ch = &chcopy;
		int err;

		WLTRACE("  ident=0x%llx filter=%d flags=0x%x fflags=0x%x qos=0x%x ext=%llx,%llx,%llx,%llx\n",
			(unsigned long long) ch->ident, ch->filter, ch->flags, ch->fflags, ch->qos,
			(unsigned long long) ch->ext[0], (unsigned long long) ch->ext[1],
			(unsigned long long) ch->ext[2], (unsigned long long) ch->ext[3]);

		if (is_sync_ipc(ch))
			err = 0;
		else if (ch->filter == EVFILT_WORKLOOP)
			err = wl_change(id, ch);
		else
		{
			struct kevent64_s rc;
			int nr = wq_apply_changes(ch, 1, &rc, id);
			err = nr < 0 ? -nr : ((nr > 0 && (rc.flags & EV_ERROR)) ? rc.data : 0);
			if (ch->flags & (EV_DELETE | EV_DISABLE))
			{
				libsimple_lock_lock(&wl_lock);
				struct workloop* wl = wl_get_locked(id);
				if (wl != NULL)
					wl_purge_locked(wl, ch);
				libsimple_lock_unlock(&wl_lock);
			}
		}

		if (err == 0)
			continue;
		WLTRACE("  -> error %d\n", err);
		if (eventlist == NULL || nout >= nevents)
			return -err;
		eventlist[nout] = *ch;
		eventlist[nout].flags = ch->flags | EV_ERROR; // x86Code: XNU keeps the flags
		eventlist[nout].data = err;
		nout++;
	}

	if (flags & KEVENT_FLAG_ERROR_EVENTS)
		return nout;

	// The servicer (or a thread about to park) picks up events queued meanwhile
	if (eventlist != NULL && nevents > nout)
	{
		libsimple_lock_lock(&wl_lock);
		struct workloop* wl = wl_get_locked(id);
		if (wl != NULL && wl->npending > 0)
		{
			int n = wl->npending < nevents - nout ? wl->npending : nevents - nout;
			memmove(&eventlist[nout], wl->pending, n * sizeof(struct kevent_qos_s));
			memmove(wl->pending, &wl->pending[n], (wl->npending - n) * sizeof(struct kevent_qos_s));
			wl->npending -= n;
			nout += n;
		}
		libsimple_lock_unlock(&wl_lock);
	}
	return nout;
}
#else
long sys_kevent_id(unsigned long long id, const struct kevent_qos_s *changelist, int nchanges,
			struct kevent_qos_s *eventlist, int nevents,
			void* data_out, unsigned long* data_available, unsigned int flags)
{
	return -ENOSYS;
}
#endif
