#ifndef LINUX_PREADV_H
#define LINUX_PREADV_H

struct iovec;

long sys_preadv(int fd, struct iovec* iovp, int iovcnt, long long offset);
long sys_preadv_nocancel(int fd, struct iovec* iovp, int iovcnt, long long offset);
long sys_pwritev(int fd, struct iovec* iovp, int iovcnt, long long offset);
long sys_pwritev_nocancel(int fd, struct iovec* iovp, int iovcnt, long long offset);

#endif // LINUX_PREADV_H
