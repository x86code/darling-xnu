#ifndef LINUX_SOCKET_H
#define LINUX_SOCKET_H

long sys_socket(int domain, int type, int protocol);
long sys_socket_delegate(int domain, int type, int protocol, int epid);

#endif // LINUX_SOCKET_H
