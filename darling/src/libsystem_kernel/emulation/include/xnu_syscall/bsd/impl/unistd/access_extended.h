#ifndef LINUX_ACCESS_EXTENDED_H
#define LINUX_ACCESS_EXTENDED_H

// x86Code: access_extended (accessx_np), syscall 284
long sys_access_extended(void* entries, unsigned long size, int* results, int uid);

#endif // LINUX_ACCESS_EXTENDED_H
