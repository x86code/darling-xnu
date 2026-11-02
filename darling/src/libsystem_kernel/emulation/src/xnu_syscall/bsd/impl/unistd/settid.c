#include <darling/emulation/xnu_syscall/bsd/impl/unistd/settid.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>

#include <darlingserver/rpc.h>

extern volatile int __darling_settid_active;

// XNU's KAUTH_UID_NONE / KAUTH_GID_NONE: settid(NONE, NONE) gives up the assumed identity
#define DARLING_KAUTH_ID_NONE ((int)(~0u - 100))

long sys_settid(int uid, int gid)
{
	if (uid == DARLING_KAUTH_ID_NONE && gid == DARLING_KAUTH_ID_NONE) {
		__darling_settid_active = 0;
		return 0;
	}
	long r = __setuidgid(uid, gid);
	if (r == 0)
		__darling_settid_active = 1;
	return r;
}
