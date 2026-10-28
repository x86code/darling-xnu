#ifndef LINUX_GUARDED_IO_NP_H
#define LINUX_GUARDED_IO_NP_H

#include <stdint.h>

struct iovec;

// x86Code: BSD syscalls 484-487
long sys_guarded_open_dprotected_np(const char* path, const uint64_t* guard, unsigned int guardflags, int flags,
		int dpclass, int dpflags, int mode);
long sys_guarded_write_np(int fd, const uint64_t* guard, const void* buf, unsigned long nbyte);
long sys_guarded_pwrite_np(int fd, const uint64_t* guard, const void* buf, unsigned long nbyte, long long offset);
long sys_guarded_writev_np(int fd, const uint64_t* guard, struct iovec* iovp, int iovcnt);

#endif // LINUX_GUARDED_IO_NP_H
