#include <darling/emulation/xnu_syscall/bsd/impl/network/setsockopt.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/xnu_syscall/bsd/impl/network/getsockopt.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/network/getsockopt.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/time/gettimeofday.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/nosigpipe.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockextra.h>

#define LINGER_TICKS_PER_SEC	100 // Is this the right number of ticks per sec?

long sys_setsockopt(int fd, int level, int optname, const void* optval, int optlen)
{
	int ret, linux_level, linux_optname;
	char buf[100];
	long route_ret;

	if (ROUTE_SOCKET_ACTIVE() && route_socket_sockopt(fd, 1, level, optname, (void*) optval, &optlen, &route_ret))
		return route_ret;

	// XNU's SOF_NOSIGPIPE (sooptcopyin() of an int)
	if (level == BSD_SOL_SOCKET && optname == BSD_SO_NOSIGNAL) {
		if (optval == NULL || optlen < (int) sizeof(int))
			return -EINVAL;
		return socket_nosigpipe_set(fd, *(const int*) optval != 0);
	}

	// x86Sim: IP_BOUND_IF / IPV6_BOUND_IF (XNU's interface scoping, netinet/in.h 25, netinet6/in6.h 125): Network.framework
	// binds every flow's socket to its path's interface; ENOTSUP failed the flow with ENETDOWN (NSURLErrorNotConnected).
	// Linux's equivalent is SO_BINDTOIFINDEX (an index of 0 unbinds, as on XNU).
	if ((level == 0 && optname == 25) || (level == 41 && optname == 125)) {
		if (optval == NULL || optlen < (int) sizeof(int))
			return -EINVAL;
		int ifindex = *(const int*) optval;
#ifdef __NR_socketcall
		ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SETSOCKOPT,
				((long[6]) { fd, 1 /* SOL_SOCKET */, 62 /* SO_BINDTOIFINDEX */, &ifindex, sizeof(ifindex), 0 }));
#else
		ret = LINUX_SYSCALL(__NR_setsockopt, fd, 1 /* SOL_SOCKET */, 62 /* SO_BINDTOIFINDEX */, &ifindex, sizeof(ifindex));
#endif
		return ret < 0 ? errno_linux_to_bsd(ret) : 0;
	}

	// x86Sim: options Network.framework sets on every flow, answered as XNU does (sockextra.h)
	if (level == BSD_SOL_SOCKET && optname == BSD_SO_CONNECTION_IDLE)
		return sockextra_set_idle(fd, optval, optlen);
	// SO_DEFUNCTOK (dnssd_clientstub sets it on every connection; EINVAL was logged): sockets are never defuncted
	// here, so whether one may be is moot. XNU takes an int.
	if (level == BSD_SOL_SOCKET && optname == BSD_SO_DEFUNCTOK)
		return (optval == NULL || optlen < (int) sizeof(int)) ? -EINVAL : 0;
	if ((level == 0 && optname == BSD_IP_OUT_IF) || (level == 41 && optname == BSD_IPV6_OUT_IF))
		return -EINVAL; // not settable (ip_ctloutput)
	if (level == XNU_IPPROTO_TCP && optname == BSD_TCP_NOTSENT_LOWAT) {
#ifdef __NR_socketcall
		ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SETSOCKOPT,
				((long[6]) { fd, 6, LINUX_TCP_NOTSENT_LOWAT, optval, optlen, 0 }));
#else
		ret = LINUX_SYSCALL(__NR_setsockopt, fd, 6, LINUX_TCP_NOTSENT_LOWAT, optval, optlen);
#endif
		return ret < 0 ? errno_linux_to_bsd(ret) : 0;
	}

	linux_level = level;
	linux_optname = optname;
	
	ret = sockopt_bsd_to_linux(&linux_level, &linux_optname,
			(void**) &optval, buf);
	
	if (ret != 0 || !linux_optname)
		return ret;

	if (level == BSD_SOL_SOCKET)
	{
		if (optname == BSD_SO_RCVTIMEO || optname == BSD_SO_SNDTIMEO)
		{
			if (optlen < (int)sizeof(struct bsd_timeval))
				return -EINVAL;
			if (!optval)
				return -EFAULT;
			const struct bsd_timeval* tv = (const struct bsd_timeval*) optval;
			if ((long)tv->tv_sec < 0 || tv->tv_usec < 0 || tv->tv_usec >= 1000000)
				return -EDOM;
			struct linux_timeval* ltv = (struct linux_timeval*) __builtin_alloca(sizeof(struct linux_timeval));

			ltv->tv_sec = tv->tv_sec;
			ltv->tv_usec = tv->tv_usec;

			optval = ltv;
			optlen = sizeof(*ltv);
		}
	}

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SETSOCKOPT,
			((long[6]) { fd, linux_level, linux_optname, optval, optlen, 0 }));
#else
	ret = LINUX_SYSCALL(__NR_setsockopt, fd, linux_level, linux_optname,
			optval, optlen);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
