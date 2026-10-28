// x86Code: guarded_open_dprotected_np, guarded_write_np, guarded_pwrite_np and guarded_writev_np (BSD syscalls
// 484-487). SpotlightIndex (searchd) writes every index file through guarded_pwrite_np; with ENOSYS its first write
// (indexState) failed, the index was never created ("Not fully created") and every CoreSpotlight query (Files and
// Preview Recents, Spotlight search) failed with CSSearchQueryErrorDomain -2001. Darling enforces no guards (see
// change_fdguard_np.c), so these are the unguarded calls. XNU's write paths also refuse a guard that doesn't match
// (EPERM); with no guards kept that can't be checked.
#include <darling/emulation/xnu_syscall/bsd/impl/guarded/guarded_io_np.h>

#include <stddef.h>
#include <sys/errno.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/pwrite.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/writev.h>
#include <darling/emulation/xnu_syscall/bsd/impl/hfs/stub.h>

long sys_guarded_open_dprotected_np(const char* path, const uint64_t* guard, unsigned int guardflags, int flags,
		int dpclass, int dpflags, int mode)
{
	if (guard == NULL)
		return -EINVAL;
	return sys_open_dprotected_np(path, flags, dpclass, dpflags, mode);
}

long sys_guarded_write_np(int fd, const uint64_t* guard, const void* buf, unsigned long nbyte)
{
	return sys_write(fd, buf, (int) nbyte);
}

long sys_guarded_pwrite_np(int fd, const uint64_t* guard, const void* buf, unsigned long nbyte, long long offset)
{
	return sys_pwrite(fd, buf, (int) nbyte, offset);
}

long sys_guarded_writev_np(int fd, const uint64_t* guard, struct iovec* iovp, int iovcnt)
{
	return sys_writev(fd, iovp, (unsigned int) iovcnt);
}
