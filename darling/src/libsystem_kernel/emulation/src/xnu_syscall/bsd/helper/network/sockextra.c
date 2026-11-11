// x86Sim: see sockextra.h
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockextra.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/tcpinfo.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/getsockname.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/getpeername.h>

extern void* memset(void* dest, int c, __SIZE_TYPE__ n);
extern int memcmp(const void* a, const void* b, __SIZE_TYPE__ n);

#define L_AF_INET 2
#define L_AF_INET6 10
#define L_SOL_SOCKET 1
#define L_SO_ERROR 4
#define L_SO_DOMAIN 39
#define L_SO_BINDTOIFINDEX 62
#define L_SIOCGIFCONF 0x8912
#define L_SIOCGIFINDEX 0x8933

static long l_getsockopt(int fd, int level, int name, void* val, unsigned int* len)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT, ((long[6]) { fd, level, name, val, len, 0 }));
#else
	return LINUX_SYSCALL(__NR_getsockopt, fd, level, name, val, len);
#endif
}

static long l_name(int fd, int peer, void* sa, unsigned int* len)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, peer ? LINUX_SYS_GETPEERNAME : LINUX_SYS_GETSOCKNAME, ((long[6]) { fd, sa, len }));
#else
	return LINUX_SYSCALL(peer ? __NR_getpeername : __NR_getsockname, fd, sa, len);
#endif
}

static int l_domain(int fd)
{
	int d = 0;
	unsigned int len = sizeof(d);
	return l_getsockopt(fd, L_SOL_SOCKET, L_SO_DOMAIN, &d, &len) < 0 ? -1 : d;
}

int sockextra_unix_dgram(int fd)
{
	int t = 0;
	unsigned int len = sizeof(t);
	if (l_getsockopt(fd, L_SOL_SOCKET, 3 /* SO_TYPE */, &t, &len) < 0 || t != 2 /* SOCK_DGRAM */)
		return 0;
	return l_domain(fd) == 1 /* AF_UNIX */;
}

struct l_ifreq { char name[16]; union { struct { uint16_t family, port; uint32_t addr; } in; int index; char pad[24]; }; };
struct l_ifconf { int len; int pad; void* buf; };

static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }

int sockextra_out_ifindex(int fd)
{
	int bound = 0;
	unsigned int len = sizeof(bound);
	if (l_getsockopt(fd, L_SOL_SOCKET, L_SO_BINDTOIFINDEX, &bound, &len) >= 0 && bound > 0)
		return bound;

	unsigned char sa[128];
	len = sizeof(sa);
	if (l_name(fd, 0, sa, &len) < 0)
		return 0;
	uint16_t family = *(uint16_t*) sa;

	if (family == L_AF_INET) {
		uint32_t addr = *(uint32_t*) (sa + 4);
		if (addr == 0)
			return 0; // not bound: no traffic yet
		struct l_ifreq reqs[32];
		struct l_ifconf conf = { sizeof(reqs), 0, reqs };
		int s = fd;
		if (LINUX_SYSCALL(__NR_ioctl, s, L_SIOCGIFCONF, &conf) < 0)
			return 0;
		for (int i = 0; i < conf.len / (int) sizeof(struct l_ifreq); i++) {
			if (reqs[i].in.family == L_AF_INET && reqs[i].in.addr == addr) {
				struct l_ifreq q;
				memset(&q, 0, sizeof(q));
				for (int k = 0; k < 16; k++) q.name[k] = reqs[i].name[k];
				if (LINUX_SYSCALL(__NR_ioctl, s, L_SIOCGIFINDEX, &q) < 0)
					return 0;
				return q.index;
			}
		}
		return 0;
	}
	if (family == L_AF_INET6) {
		const unsigned char* a6 = sa + 8;
		static const unsigned char zero[16];
		if (!memcmp(a6, zero, 16))
			return 0;
		// IPv4-mapped: the IPv4 interface is not in if_inet6; leave it to the caller (0)
		// /proc/net/if_inet6: "<32 hex addr> <ifindex hex> <plen> <scope> <flags> <name>"
		int f = LINUX_SYSCALL(__NR_openat, -100, "/proc/net/if_inet6", 0, 0);
		if (f < 0)
			return 0;
		static char buf[8192];
		long n = LINUX_SYSCALL(__NR_read, f, buf, sizeof(buf) - 1);
		LINUX_SYSCALL(__NR_close, f);
		if (n <= 0)
			return 0;
		buf[n] = 0;
		for (char* line = buf; *line; ) {
			unsigned char addr[16];
			int ok = 1;
			for (int k = 0; k < 16; k++) {
				int h = hexval(line[2 * k]), l = hexval(line[2 * k + 1]);
				if (h < 0 || l < 0) { ok = 0; break; }
				addr[k] = (unsigned char) (h * 16 + l);
			}
			if (ok && !memcmp(addr, a6, 16)) {
				int idx = 0;
				char* p = line + 33;
				while (hexval(*p) >= 0) idx = idx * 16 + hexval(*p++);
				return idx;
			}
			while (*line && *line != '\n') line++;
			if (*line) line++;
		}
	}
	return 0;
}

// XNU keeps the flag in the inpcb (INP2_CONNECTION_IDLE); here per descriptor, cleared when it is closed
#define IDLE_FDS 8192
static unsigned char idle_flags[IDLE_FDS / 8];

long sockextra_set_idle(int fd, const void* optval, int optlen)
{
	int d = l_domain(fd);
	if (d < 0)
		return -ENOTSOCK;
	if (d != L_AF_INET && d != L_AF_INET6)
		return -EINVAL;
	if (optval == NULL || optlen < (int) sizeof(int))
		return -EINVAL;
	if (fd >= 0 && fd < IDLE_FDS) {
		if (*(const int*) optval)
			idle_flags[fd / 8] |= (unsigned char) (1 << (fd % 8));
		else
			idle_flags[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
	}
	return 0;
}

long sockextra_get_idle(int fd, void* optval, int* optlen)
{
	int d = l_domain(fd);
	if (d < 0)
		return -ENOTSOCK;
	if (d != L_AF_INET && d != L_AF_INET6)
		return -EINVAL;
	if (optlen == NULL)
		return -EFAULT;
	int v = (fd >= 0 && fd < IDLE_FDS) ? !!(idle_flags[fd / 8] & (1 << (fd % 8))) : 0;
	if (optval == NULL) { *optlen = 0; return 0; }
	int n = *optlen < (int) sizeof(v) ? *optlen : (int) sizeof(v);
	if (n < 0)
		return -EINVAL;
	for (int i = 0; i < n; i++) ((char*) optval)[i] = ((char*) &v)[i];
	*optlen = n;
	return 0;
}

void sockextra_closed(int fd)
{
	if (fd >= 0 && fd < IDLE_FDS)
		idle_flags[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
}

// XNU's struct so_cinforeq (64-bit user), bsd/sys/socket_private.h
struct xnu_so_cinforeq {
	uint32_t scir_cid;
	uint32_t scir_flags;
	uint32_t scir_ifindex;
	int32_t scir_error;
	void* scir_src;
	uint32_t scir_src_len;
	void* scir_dst __attribute__((aligned(8)));
	uint32_t scir_dst_len;
	uint32_t scir_aux_type;
	void* scir_aux_data;
	uint32_t scir_aux_len;
};
_Static_assert(sizeof(struct xnu_so_cinforeq) == 64, "so_cinforeq is 64 bytes");
#define CIF_CONNECTED 0x2
#define CIF_BOUND_IF 0x10
#define CIF_BOUND_IP 0x20
#define CIAUX_TCP 0x1
#define SAE_CONNID_ANY 0
#define SAE_CONNID_ALL ((uint32_t) -1)

long sockextra_conninfo(int fd, void* arg)
{
	struct xnu_so_cinforeq* r = arg;
	int d = l_domain(fd);
	if (d < 0)
		return -ENOTSOCK;
	if (d != L_AF_INET && d != L_AF_INET6)
		return -EINVAL; // as XNU: in_getconninfo is the INET protocols'
	// XNU (in_getconninfo): only SAE_CONNID_ANY/ALL or the socket's one connection (1)
	if (r->scir_cid != SAE_CONNID_ANY && r->scir_cid != SAE_CONNID_ALL && r->scir_cid != 1)
		return -EINVAL;

	uint32_t flags = 0;
	unsigned char sa[128];
	unsigned int len = sizeof(sa);
	if (l_name(fd, 1, sa, &len) >= 0)
		flags |= CIF_CONNECTED;
	int bound = 0;
	len = sizeof(bound);
	if (l_getsockopt(fd, L_SOL_SOCKET, L_SO_BINDTOIFINDEX, &bound, &len) >= 0 && bound > 0)
		flags |= CIF_BOUND_IF;
	int err = 0;
	len = sizeof(err);
	l_getsockopt(fd, L_SOL_SOCKET, L_SO_ERROR, &err, &len);

	r->scir_flags = flags;
	r->scir_ifindex = sockextra_out_ifindex(fd);
	r->scir_error = err ? errno_linux_to_bsd(-err) * -1 : 0;

	// addresses: copied out up to the length given (XNU copies min(len, sa_len) and returns the full length)
	if (r->scir_src && r->scir_src_len > 0) {
		unsigned char tmp[128];
		int l = sizeof(tmp);
		if (sys_getsockname(fd, tmp, &l) == 0) {
			int n = (int) r->scir_src_len < l ? (int) r->scir_src_len : l;
			for (int i = 0; i < n; i++) ((unsigned char*) r->scir_src)[i] = tmp[i];
			r->scir_src_len = l;
		} else r->scir_src_len = 0;
	}
	if (r->scir_dst && r->scir_dst_len > 0) {
		unsigned char tmp[128];
		int l = sizeof(tmp);
		if (sys_getpeername(fd, tmp, &l) == 0) {
			int n = (int) r->scir_dst_len < l ? (int) r->scir_dst_len : l;
			for (int i = 0; i < n; i++) ((unsigned char*) r->scir_dst)[i] = tmp[i];
			r->scir_dst_len = l;
		} else r->scir_dst_len = 0;
	}

	// aux: a TCP socket's tcp_connection_info (CIAUX_TCP), as XNU's tcp_getconninfo()
	int type = 0;
	len = sizeof(type);
	l_getsockopt(fd, L_SOL_SOCKET, 3 /* SO_TYPE */, &type, &len);
	if (type == 1 /* SOCK_STREAM */) {
		r->scir_aux_type = CIAUX_TCP;
		if (r->scir_aux_data && r->scir_aux_len >= sizeof(struct xnu_tcp_connection_info)) {
			int l = sizeof(struct xnu_tcp_connection_info);
			if (tcp_info_option(fd, BSD_TCP_CONNECTION_INFO, r->scir_aux_data, &l) == 0)
				r->scir_aux_len = l;
		} else {
			r->scir_aux_len = sizeof(struct xnu_tcp_connection_info);
		}
	} else {
		r->scir_aux_type = 0;
		r->scir_aux_len = 0;
	}
	return 0;
}

// XNU's IFRTYPE_FUNCTIONAL_* (net/if.h)
#define IFRTYPE_FUNCTIONAL_UNKNOWN 0
#define IFRTYPE_FUNCTIONAL_LOOPBACK 1
#define IFRTYPE_FUNCTIONAL_WIRED 2
#define IFRTYPE_FUNCTIONAL_WIFI_INFRA 3
#define L_SIOCGIFHWADDR 0x8927
#define L_SIOCGIWNAME 0x8b01
#define L_ARPHRD_ETHER 1
#define L_ARPHRD_LOOPBACK 772

// The interface's functional type from Linux's link type: loopback, Wi-Fi (a wireless extension answers SIOCGIWNAME),
// other Ethernet as wired, anything else unknown. Network.framework's nw_path interface type comes from this (it was
// passed through to Linux and failed): GeoServices' GEONetworkObserver counts a satisfied path as reachable only over
// Wi-Fi, cellular or wired, so Maps showed "No Internet Connection" over an "other" interface.
#define L_SIOCGIFMTU 0x8921

long sockextra_mtu(int fd, void* arg)
{
	struct { char name[16]; int mtu; char pad[20]; } q;
	char* ifr = arg;
	memset(&q, 0, sizeof(q));
	for (int i = 0; i < 15 && ifr[i]; i++) q.name[i] = ifr[i];
	long r = LINUX_SYSCALL(__NR_ioctl, fd, L_SIOCGIFMTU, &q);
	if (r < 0)
		return errno_linux_to_bsd(r);
	*(int*) (ifr + 16) = q.mtu;
	return 0;
}

long sockextra_functional_type(int fd, void* arg)
{
	struct { char name[16]; union { struct { uint16_t family; char data[14]; } hw; uint32_t ftype; char pad[16]; }; } q;
	char* ifr = arg;
	memset(&q, 0, sizeof(q));
	for (int i = 0; i < 15 && ifr[i]; i++) q.name[i] = ifr[i];
	long r = LINUX_SYSCALL(__NR_ioctl, fd, L_SIOCGIFHWADDR, &q);
	if (r < 0)
		return errno_linux_to_bsd(r); // ENXIO for an unknown interface, as XNU
	uint32_t type = IFRTYPE_FUNCTIONAL_UNKNOWN;
	if (q.hw.family == L_ARPHRD_LOOPBACK)
		type = IFRTYPE_FUNCTIONAL_LOOPBACK;
	else if (q.hw.family == L_ARPHRD_ETHER) {
		char w[32];
		memset(w, 0, sizeof(w));
		for (int i = 0; i < 15 && ifr[i]; i++) w[i] = ifr[i];
		type = LINUX_SYSCALL(__NR_ioctl, fd, L_SIOCGIWNAME, w) >= 0 ? IFRTYPE_FUNCTIONAL_WIFI_INFRA : IFRTYPE_FUNCTIONAL_WIRED;
	}
	*(uint32_t*) (ifr + 16) = type;
	return 0;
}
