#include <darling/emulation/xnu_syscall/bsd/impl/network/connect.h>

#include <sys/socket.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/other/mach/foreign_hook.h>

extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern __SIZE_TYPE__ strlen(const char* src);
extern char* strcpy(char* dest, const char* src);
extern char *strncpy(char *dest, const char *src, __SIZE_TYPE__ n);

// libkqueue's, when it's there (for-libkqueue.h)
__attribute__((weak))
__attribute__((visibility("default")))
void kqueue_socket_changed(int fd)
{
	// x86Code: on the simulator's libSystem libkqueue is libkqueue_sim, found by name (foreign_hook.h)
	FOREIGN_HOOK(void (*)(int), foreign, "__darling_sim_kqueue_socket_changed");
	if (foreign)
		foreign(fd);
}

// Must be included after strncpy
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

long sys_connect(int fd, const void* name, int socklen)
{
	CANCELATION_POINT();
	return sys_connect_nocancel(fd, name, socklen);
}

long sys_connect_nocancel(int fd, const void* name, int socklen)
{
	int ret;
	int linux_domain;
	struct sockaddr_fixup* fixed;

	if (socklen > 512)
		return -EINVAL;

	fixed = __builtin_alloca(sockaddr_fixup_size_from_bsd(name, socklen));
	ret = socklen = sockaddr_fixup_from_bsd(fixed, name, socklen);
	if (ret < 0)
		return ret;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_CONNECT, ((long[6]) { fd, fixed, socklen }));
#else
	ret = LINUX_SYSCALL(__NR_connect, fd, fixed, socklen);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	// connected, or failed; a connect still in progress changes nothing yet
	if (ret != -EINPROGRESS && ret != -EALREADY)
		SOCKET_CHANGED(fd);

	return ret;
}

// x86Code: connectx (BSD 447). iOS 27's Network.framework opens every TCP flow with connectx(), not connect(); without it
// the call failed and NSURLSession reported "The Internet connection appears to be offline" (ENETDOWN on the flow).
// sa_endpoints_t: sae_srcif (u32), sae_srcaddr, sae_srcaddrlen, sae_dstaddr, sae_dstaddrlen. A source address is bound
// first; the interface index (IP_BOUND_IF) is advisory here. Data passed with the call (TCP fast open / resume on
// read-write) is not sent: *len = 0 tells the caller none was written, and it writes it once connected.
struct bsd_sa_endpoints {
	unsigned int sae_srcif;
	const void* sae_srcaddr;
	unsigned int sae_srcaddrlen;
	const void* sae_dstaddr;
	unsigned int sae_dstaddrlen;
};
extern long sys_bind(int fd, const void* name, int socklen);

long sys_connectx(int fd, const void* endpoints, unsigned int associd, unsigned int flags, const void* iov,
		unsigned int iovcnt, unsigned long* len, unsigned int* connid)
{
	const struct bsd_sa_endpoints* ep = (const struct bsd_sa_endpoints*) endpoints;
	long ret;

	CANCELATION_POINT();
	if (!ep || !ep->sae_dstaddr || !ep->sae_dstaddrlen)
		return -EINVAL;
	if (len)
		*len = 0;
	if (ep->sae_srcaddr && ep->sae_srcaddrlen)
	{
		ret = sys_bind(fd, ep->sae_srcaddr, ep->sae_srcaddrlen);
		if (ret < 0)
			return ret;
	}
	ret = sys_connect_nocancel(fd, ep->sae_dstaddr, ep->sae_dstaddrlen);
	if (ret < 0)
		return ret;
	if (connid)
		*connid = 1;
	return 0;
}

// x86Code: disconnectx (BSD 448): one connection per socket here (connectx's id 1): shut it down both ways
extern long sys_shutdown(int fd, int how);
long sys_disconnectx(int fd, unsigned int associd, unsigned int connid)
{
	(void) associd; (void) connid;
	return sys_shutdown(fd, 2 /* SHUT_RDWR */);
}
