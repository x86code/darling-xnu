// x86Sim: ported from willi/darling-xnu#8 (research/willi/darling-xnu-8.diff); see FINDINGS.md "Spike 3.8"
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockutil.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define LINUX_SOL_SOCKET 1
#define LINUX_SO_COOKIE 57
#define LINUX_SOL_TCP 6
#define LINUX_TCP_INFO 11
#define LINUX_SYS_GETSOCKOPT 15
#define LINUX_EINVAL 22

long linux_getsockopt(int fd, int level, int name, void* value, unsigned int* len)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT, ((long[6]) { fd, level, name, value, len, 0 }));
#else
	return LINUX_SYSCALL(__NR_getsockopt, fd, level, name, value, len);
#endif
}

long linux_socket_cookie(int fd, unsigned long long* cookie)
{
	unsigned int len = sizeof(*cookie);
	return linux_getsockopt(fd, LINUX_SOL_SOCKET, LINUX_SO_COOKIE, cookie, &len);
}

long linux_tcp_info(int fd, struct linux_tcp_info* info)
{
	unsigned int len = sizeof(*info);
	long ret = linux_getsockopt(fd, LINUX_SOL_TCP, LINUX_TCP_INFO, info, &len);

	// x86Sim (Speed 27): Linux's tcp_get_info() reads the state without the socket's lock, so a read that races
	// connect() on another thread can see CLOSE with the SYN already counted (segs_out 1). That reads as a socket
	// that was connected and is closed now (sostate.c: disconnected): libkqueue then kept a new socket's hang-up as
	// EOF and Network.framework failed the connection "Network is down" (the first connection of mobileassetd,
	// WebKit's Networking process ...). connect() sets SYN_SENT before it sends, so one more read is consistent.
	if (ret == 0 && len >= sizeof(*info) && info->state == LINUX_TCP_CLOSE && (info->segs_out || info->segs_in))
	{
		len = sizeof(*info);
		ret = linux_getsockopt(fd, LINUX_SOL_TCP, LINUX_TCP_INFO, info, &len);
	}

	// a kernel whose tcp_info is shorter than this one's (before 4.2)
	if (ret == 0 && len < sizeof(*info))
		return -LINUX_EINVAL;
	return ret;
}
