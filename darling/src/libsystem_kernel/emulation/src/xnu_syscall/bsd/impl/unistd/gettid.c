#include <darling/emulation/xnu_syscall/bsd/impl/unistd/gettid.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>

#include <darlingserver/rpc.h>

// x86Sim: set by sys_settid (settid.c) while an identity assumed with settid() is in effect.
volatile int __darling_settid_active = 0;

// x86Sim: as XNU's gettid(): a thread without an identity assumed through settid() (UT_SETUID) gets ESRCH and the
// pointers are not touched. Darling wrote through them unconditionally, so code calling syscall(SYS_gettid) the Linux
// way (glog/folly in React Native's ReactNativeDependencies: x1 = junk) crashed the app with SIGSEGV on its first log.
long sys_gettid(int* uid, int* gid)
{
	if (!__darling_settid_active)
		return -ESRCH;
	if (uid == NULL || gid == NULL)
		return -EFAULT;
	__getuidgid(uid, gid);
	return 0;
}
