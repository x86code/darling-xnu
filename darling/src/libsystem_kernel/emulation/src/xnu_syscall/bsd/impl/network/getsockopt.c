#include <darling/emulation/xnu_syscall/bsd/impl/network/getsockopt.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/network/getsockopt.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/impl/time/gettimeofday.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/nosigpipe.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/tcpinfo.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockextra.h>

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);

#define LINUX_FIONREAD 0x541B
#define LINUX_EINVAL 22
#define LINUX_SOL_SOCKET 1
#define LINUX_SO_TYPE 3

// XNU's getsockopt() and sooptcopyout() of an int option: as much of it as fits, none without a buffer; the length
// is copied in and out (EFAULT without it)
static long int_option(int value, void* optval, int* optlen)
{
	if (optlen == NULL)
		return -EFAULT;
	if (optval == NULL) {
		*optlen = 0;
		return 0;
	}

	int n = *optlen < (int) sizeof(value) ? *optlen : (int) sizeof(value);

	if (n < 0)
		return -EINVAL;
	memcpy(optval, &value, n);
	*optlen = n;
	return 0;
}

// SO_NREAD (XNU's sogetoptlock()): the bytes a stream socket has to read, or the first datagram's; Linux's FIONREAD
// (SIOCINQ) is the same, but refuses a listening TCP socket, which has none
static long so_nread(int fd, void* optval, int* optlen)
{
	int n = 0, type;
	unsigned int len = sizeof(type);
	long ret;

	// a socket? (ENOTSOCK if not)
#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT, ((long[6]) { fd, LINUX_SOL_SOCKET, LINUX_SO_TYPE, &type, &len }));
#else
	ret = LINUX_SYSCALL(__NR_getsockopt, fd, LINUX_SOL_SOCKET, LINUX_SO_TYPE, &type, &len);
#endif

	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = LINUX_SYSCALL(__NR_ioctl, fd, LINUX_FIONREAD, &n);
	if (ret == -LINUX_EINVAL)
		n = 0;
	else if (ret < 0)
		return errno_linux_to_bsd(ret);
	return int_option(n, optval, optlen);
}

long sys_getsockopt(int fd, int level, int optname, void* optval, int* optlen)
{
	int ret, linux_level, linux_optname;
	long route_ret;

	if (ROUTE_SOCKET_ACTIVE() && route_socket_sockopt(fd, 0, level, optname, optval, optlen, &route_ret))
		return route_ret;

	if (level == BSD_SOL_SOCKET && optname == BSD_SO_NREAD)
		return so_nread(fd, optval, optlen);
	if (level == BSD_SOL_SOCKET && optname == BSD_SO_NOSIGNAL) {
		int on;
		ret = socket_nosigpipe_get(fd, &on);
		return ret < 0 ? ret : int_option(on, optval, optlen);
	}
	// x86Sim: willi/darling-xnu#25: TCP_INFO / TCP_CONNECTION_INFO from Linux's TCP_INFO
	if (level == XNU_IPPROTO_TCP && (optname == BSD_TCP_INFO || optname == BSD_TCP_CONNECTION_INFO))
		return tcp_info_option(fd, optname, optval, optlen);

	// x86Sim: IP_BOUND_IF / IPV6_BOUND_IF read back Linux's SO_BINDTOIFINDEX (setsockopt.c)
	if ((level == 0 && optname == 25) || (level == 41 && optname == 125)) {
		int ifindex = 0, len = sizeof(ifindex);
#ifdef __NR_socketcall
		ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT,
				((long[6]) { fd, 1 /* SOL_SOCKET */, 62 /* SO_BINDTOIFINDEX */, &ifindex, &len, 0 }));
#else
		ret = LINUX_SYSCALL(__NR_getsockopt, fd, 1 /* SOL_SOCKET */, 62 /* SO_BINDTOIFINDEX */, &ifindex, &len);
#endif
		return ret < 0 ? errno_linux_to_bsd(ret) : int_option(ifindex, optval, optlen);
	}

	// x86Sim: answered as XNU does (sockextra.h)
	if (level == BSD_SOL_SOCKET && optname == BSD_SO_CONNECTION_IDLE)
		return sockextra_get_idle(fd, optval, optlen);
	if (level == BSD_SOL_SOCKET && optname == BSD_SO_DEFUNCTOK)
		return int_option(1, optval, optlen); // XNU: !(so_flags & SOF_NODEFUNCT)
	if ((level == 0 && optname == BSD_IP_OUT_IF) || (level == 41 && optname == BSD_IPV6_OUT_IF))
		return int_option(sockextra_out_ifindex(fd), optval, optlen);
	if (level == XNU_IPPROTO_TCP && optname == BSD_TCP_NOTSENT_LOWAT) {
#ifdef __NR_socketcall
		ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT,
				((long[6]) { fd, 6, LINUX_TCP_NOTSENT_LOWAT, optval, optlen, 0 }));
#else
		ret = LINUX_SYSCALL(__NR_getsockopt, fd, 6, LINUX_TCP_NOTSENT_LOWAT, optval, optlen);
#endif
		return ret < 0 ? errno_linux_to_bsd(ret) : 0;
	}

	linux_level = level;
	linux_optname = optname;
	
	ret = sockopt_bsd_to_linux(&linux_level, &linux_optname, NULL, optval);
	
	if (ret != 0 || !linux_optname)
		return ret;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT,
			((long[6]) { fd, linux_level, linux_optname, optval, optlen, 0 }));
#else
	ret = LINUX_SYSCALL(__NR_getsockopt, fd, linux_level, linux_optname,
			optval, optlen);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else
	{
		if (level == BSD_SOL_SOCKET)
		{
			if (optname == BSD_SO_LINGER_TICKS)
			{
				struct xnu_linger* l = (struct xnu_linger*) optval;
				l->l_linger *= LINGER_TICKS_PER_SEC;
			}
			else if (optname == BSD_SO_ERROR)
			{
				int* err = (int*) optval;
				if (err && *err)
					*err = errno_linux_to_bsd(*err);
				// an error EVFILT_SOCK took from Linux, held for this (sostate.h)
				if (err && SOCKET_ERROR_OPT_HOOKED(*err))
					*err = socket_error_take(fd, *err);
			}
			else if ((optname == BSD_SO_RCVTIMEO || optname == BSD_SO_SNDTIMEO)
					&& optval && optlen && *optlen >= (int)sizeof(struct linux_timeval))
			{
				// Linux returns a timeval with a long tv_usec; Darwin's is
				// 32 bits followed by padding. The layouts only differ on
				// big-endian (PPC), but convert both timeouts the same way.
				struct linux_timeval ltv = *((struct linux_timeval*) optval);
				struct bsd_timeval* btv = (struct bsd_timeval*) optval;
				btv->tv_sec = ltv.tv_sec;
				btv->tv_usec = ltv.tv_usec;
			}
		}
	}

	return ret;
}
