#include <darling/emulation/xnu_syscall/bsd/impl/network/sendto.h>

#include <sys/errno.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/socktables.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockextra.h>

extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);

long sys_sendto(int fd, const void* buffer, unsigned long length,
		int flags, const void* sockaddr, int socklen)
{
	CANCELATION_POINT();
	return sys_sendto_nocancel(fd, buffer, length, flags, sockaddr, socklen);
}

long sys_sendto_nocancel(int fd, const void* buffer, unsigned long length,
		int flags, const void* sockaddr, int socklen)
{
	int ret, linux_flags;

	struct sockaddr_fixup* fixed = NULL;
	long route_ret;

	// x86Sim: PF_ROUTE sockets (willi/darling-xnu#7) are answered in the writer's thread
	if (ROUTE_SOCKET_ACTIVE() && route_socket_write(fd, buffer, length, sockaddr != NULL, &route_ret))
		return route_ret;

	if (socklen > 512)
		return -EINVAL;

	if (sockaddr != NULL) {
		fixed = __builtin_alloca(sockaddr_fixup_size_from_bsd(sockaddr, socklen));
		ret = socklen = sockaddr_fixup_from_bsd(fixed, sockaddr, socklen);
		if (ret < 0)
			return ret;
	}

	// x86Sim: willi/darling-xnu#8: Linux never raises SIGPIPE; XNU's is raised below unless SO_NOSIGPIPE/MSG_NOSIGNAL
	linux_flags = msgflags_bsd_to_linux(flags) | LINUX_MSG_NOSIGNAL;
	// x86Sim: a local datagram send never blocks, as on XNU (sockextra.h)
	const int unix_dgram = sockextra_unix_dgram(fd);
	if (unix_dgram)
		linux_flags |= LINUX_MSG_DONTWAIT;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SENDTO,
			((long[6]) { fd, buffer, length, linux_flags, fixed, socklen }));
#else
	ret = LINUX_SYSCALL(__NR_sendto, fd, buffer, length,
			linux_flags, fixed, socklen);
#endif

	if (ret < 0) {
		ret = errno_linux_to_bsd(ret);
		if (unix_dgram && ret == -EAGAIN)
			ret = -ENOBUFS;
		// XNU's error, and its SIGPIPE: Linux raised none (socktables.h)
		ret = socket_send_failed(fd, ret, flags & BSD_MSG_NOSIGNAL, 0);
	}

	return ret;
}
