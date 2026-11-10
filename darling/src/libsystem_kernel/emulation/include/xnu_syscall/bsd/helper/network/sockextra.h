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
// SIOCGCONNINFO (XNU's in_getconninfo()/in6_getconninfo())
long sockextra_conninfo(int fd, void* arg);
#endif
