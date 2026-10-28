#include <darling/emulation/xnu_syscall/bsd/impl/misc/iopolicysys.h>

#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/tsd.h>
#include <darling/emulation/conversion/errno.h>

/*
 * x86Code: iopolicysys (322) keeps the policies it is given, per process and per thread, and GET returns them.
 * It used to return 0 without filling anything in, so getiopolicy_np() read back an uninitialized value.
 * NSFileCoordinator sets IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES to OFF for its thread around an accessor and
 * asserts that GET then says OFF ("materializationOffState == IOPOL_MATERIALIZE_DATALESS_FILES_OFF",
 * NSFileCoordinator.m:1002): News' widget extensions aborted there. Nothing here acts on a policy (Linux has no
 * dataless files, throttling tiers etc.); it is bookkeeping, as XNU's GET reports it. Policies are 4 bits per type
 * (types 0-15), packed into one word per scope: the thread's in a Darling TSD slot, the process's in a global.
 */
#define IOPOL_CMD_GET 0x00000001
#define IOPOL_CMD_SET 0x00000002
#define IOPOL_SCOPE_PROCESS   0
#define IOPOL_SCOPE_THREAD    1
#define IOPOL_SCOPE_DARWIN_BG 2

struct darling_iopol_param {
	int iop_scope;
	int iop_iotype;
	int iop_policy;
};


static volatile uint64_t process_policies;
static uint64_t darwin_bg_policies;

long sys_iopolicysys(int cmd, void* arg)
{
	struct darling_iopol_param* p = (struct darling_iopol_param*) arg;
	uint64_t word, mask;
	int shift;

	if (p == NULL)
		return -EFAULT;
	if (cmd != IOPOL_CMD_GET && cmd != IOPOL_CMD_SET)
		return -EINVAL;
	if (p->iop_iotype < 0 || p->iop_iotype > 15)
		return -EINVAL;
	if (p->iop_scope != IOPOL_SCOPE_PROCESS && p->iop_scope != IOPOL_SCOPE_THREAD && p->iop_scope != IOPOL_SCOPE_DARWIN_BG)
		return -EINVAL;
	if (cmd == IOPOL_CMD_SET && (p->iop_policy < 0 || p->iop_policy > 15))
		return -EINVAL;

	shift = p->iop_iotype * 4;
	mask = (uint64_t) 0xf << shift;

	switch (p->iop_scope) {
	case IOPOL_SCOPE_THREAD:
		word = (uint64_t) _pthread_getspecific_direct(__PTK_DARLING_IOPOL);
		if (cmd == IOPOL_CMD_GET)
			p->iop_policy = (int) ((word & mask) >> shift);
		else
			_pthread_setspecific_direct(__PTK_DARLING_IOPOL, (void*) ((word & ~mask) | ((uint64_t) p->iop_policy << shift)));
		break;
	case IOPOL_SCOPE_PROCESS:
		if (cmd == IOPOL_CMD_GET)
			p->iop_policy = (int) ((process_policies & mask) >> shift);
		else {
			uint64_t old, new;
			do {
				old = process_policies;
				new = (old & ~mask) | ((uint64_t) p->iop_policy << shift);
			} while (!__sync_bool_compare_and_swap(&process_policies, old, new));
		}
		break;
	default: /* IOPOL_SCOPE_DARWIN_BG */
		if (cmd == IOPOL_CMD_GET)
			p->iop_policy = (int) ((darwin_bg_policies & mask) >> shift);
		else
			darwin_bg_policies = (darwin_bg_policies & ~mask) | ((uint64_t) p->iop_policy << shift);
		break;
	}
	return 0;
}
