// x86Sim: preadv / pwritev (XNU 540-543): Linux's own (the offset as two longs, low then high, as the kernel
// takes it on 64-bit). They were missing (ENOSYS): AVAssetWriter writes its movie file with pwritev, and
// finishWriting failed with "Function not implemented" (AVFoundationErrorDomain -11800).
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/preadv.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#include <sys/errno.h>

long sys_preadv(int fd, struct iovec* iovp, int iovcnt, long long offset)
{
	CANCELATION_POINT();
	return sys_preadv_nocancel(fd, iovp, iovcnt, offset);
}

long sys_preadv_nocancel(int fd, struct iovec* iovp, int iovcnt, long long offset)
{
	if (offset < 0)
		return -EINVAL;
	long ret = LINUX_SYSCALL(__NR_preadv, fd, iovp, iovcnt, (unsigned long) offset, 0);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}

long sys_pwritev(int fd, struct iovec* iovp, int iovcnt, long long offset)
{
	CANCELATION_POINT();
	return sys_pwritev_nocancel(fd, iovp, iovcnt, offset);
}

long sys_pwritev_nocancel(int fd, struct iovec* iovp, int iovcnt, long long offset)
{
	if (offset < 0)
		return -EINVAL;
	long ret = LINUX_SYSCALL(__NR_pwritev, fd, iovp, iovcnt, (unsigned long) offset, 0);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
