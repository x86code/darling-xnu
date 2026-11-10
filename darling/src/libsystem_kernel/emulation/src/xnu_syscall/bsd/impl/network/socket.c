#include <darling/emulation/xnu_syscall/bsd/impl/network/socket.h>

#include <sys/socket.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/conversion/network/socket.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>

long sys_socket(int domain, int type, int protocol)
{
	int ret;
	int linux_domain;

	switch (domain)
	{
		case PF_LOCAL:
			linux_domain = LINUX_PF_LOCAL; break;
		case PF_INET:
			linux_domain = LINUX_PF_INET; break;
		case PF_IPX:
			linux_domain = LINUX_PF_IPX; break;
		case PF_INET6:
			linux_domain = LINUX_PF_INET6; break;
		case PF_ROUTE:
			return route_socket_create(type, protocol);
		// a domain Darling has no sockets for (PF_SYSTEM's kernel controls and events, PF_NDRV, ...; XNU has them): the
		// answer socreate_internal() gives for a domain XNU lacks, EAFNOSUPPORT
		default:
			return -EAFNOSUPPORT;
	}

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SOCKET,
			((long[6]) { linux_domain, type, protocol }));
#else
	ret = LINUX_SYSCALL(__NR_socket, linux_domain, type, protocol);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}

// x86Sim: socket_delegate (BSD 450): a socket whose traffic is attributed to another process (epid). iOS 27's
// Network.framework creates its flow sockets with it (NSURLSession in WebKit's Networking process, mobileassetd ...);
// without it no TCP socket was made and every request failed "offline". Attribution has no Linux meaning: a socket.
long sys_socket_delegate(int domain, int type, int protocol, int epid)
{
	(void) epid;
	return sys_socket(domain, type, protocol);
}
