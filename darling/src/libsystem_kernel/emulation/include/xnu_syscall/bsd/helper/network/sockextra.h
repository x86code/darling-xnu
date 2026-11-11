#ifndef NETWORK_SOCKEXTRA_H
#define NETWORK_SOCKEXTRA_H
// x86Sim: socket options and ioctls Network.framework asks for that Linux has no direct counterpart of, answered as
// XNU does (see FINDINGS.md "Spike 3.10"): IP_OUT_IF/IPV6_OUT_IF, SO_CONNECTION_IDLE, TCP_NOTSENT_LOWAT, SIOCGCONNINFO.

#define BSD_IP_OUT_IF 9696          // netinet/in_private.h (IPPROTO_IP), get only
#define BSD_IPV6_OUT_IF 9696        // netinet6/in6_private.h (IPPROTO_IPV6), get only
#define BSD_SO_CONNECTION_IDLE 0x1137 // sys/socket_private.h (SOL_SOCKET), int
#define BSD_SO_DEFUNCTOK 0x1100     // sys/socket_private.h (SOL_SOCKET), int: may be defuncted (default 1)
#define BSD_TCP_NOTSENT_LOWAT 0x201 // netinet/tcp.h
#define LINUX_TCP_NOTSENT_LOWAT 25
#define BSD_SIOCGCONNINFO 0xc0407398U // _IOWR('s', 152, struct so_cinforeq), 64 bytes on 64-bit

// the interface index the socket's traffic leaves through (0 if none yet), as XNU's inp_last_outifp
int sockextra_out_ifindex(int fd);
// SO_CONNECTION_IDLE, kept per descriptor: 0 or a negative BSD errno
long sockextra_set_idle(int fd, const void* optval, int optlen);
long sockextra_get_idle(int fd, void* optval, int* optlen);
// forget a closed descriptor's state
void sockextra_closed(int fd);
// SIOCGIFFUNCTIONALTYPE (XNU's ifnet_functional_type()): ifr is a struct ifreq; returns 0 or a negative BSD errno
#define BSD_SIOCGIFFUNCTIONALTYPE 0xc02069adU // _IOWR('i', 173, struct ifreq)
long sockextra_functional_type(int fd, void* ifr);
// x86Sim: XNU never blocks a send on a local datagram socket: a full receiver fails it with ENOBUFS (uipc_send()'s
// sbappendaddr()), where Linux sleeps until there is room. launchd_sim's dispatch workers log (os_log_simple_send())
// into launchd_sim's own CoreSimulator log socket; on a first boot they filled it, slept in sendto() with no worker
// left to drain it (Darling has no workqueue to add threads), and launchd_sim stopped answering bootstrap check-ins:
// every process hung in libxpc's initializer. 1 for an AF_UNIX SOCK_DGRAM socket: send it MSG_DONTWAIT, EAGAIN
// becomes ENOBUFS (sendto.c, sendmsg.c).
int sockextra_unix_dgram(int fd);
// SIOCGIFMTU (Linux SIOCGIFMTU on the same ifreq layout: name[16], int at +16): 0 or a negative BSD errno
long sockextra_mtu(int fd, void* ifr);
// SIOCGCONNINFO (XNU's in_getconninfo()/in6_getconninfo())
long sockextra_conninfo(int fd, void* arg);
#endif
