#ifndef WORKQ_KERNRETURN_H
#define WORKQ_KERNRETURN_H

#define PRIVATE 1
#include <sys/event.h>

// Darling specific
#define WQOPS_QUEUE_REQTHREAD_FOR_KEVENT  0x100020

struct wq_kevent_data
{
	struct kevent_qos_s* events;
	int nevents;
	int sem;
	// x86Code: deliver to __libdispatch_workloopfunction (WQ_FLAG_THREAD_WORKLOOP);
	// the workloop id must be stored just before `events`
	int workloop;
	// x86Code: number of kevent_qos_s slots at `events` (the thread may return any pointer inside)
	int capacity;
	// x86Code: if set, called on the returning thread instead of sem_up(&sem)
	void (*returned)(struct wq_kevent_data* data);
};

struct timespec;

long sys_workq_kernreturn(int options, void* item, int affinity, int prio);

int sem_down(int* sem, int timeout);
void sem_up(int* sem);

#endif // WORKQ_KERNRETURN_H
