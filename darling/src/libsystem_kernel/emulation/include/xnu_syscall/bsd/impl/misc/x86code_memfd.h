#ifndef LINUX_X86CODE_MEMFD_H
#define LINUX_X86CODE_MEMFD_H

#include <stdint.h>

// x86Code: Darling-private syscall 599, see x86code_memfd.c
long sys_x86code_memfd_for_region(uint64_t address, uint64_t size, uint64_t* out_offset, uint32_t* out_shared);

// x86Code: Darling-private syscall 598, see x86code_inotify.c
long sys_x86code_inotify(uint32_t op, uint64_t a1, uint64_t a2, uint64_t a3);

// x86Code: work_interval_ctl (BSD syscall 499), see x86code_memfd.c
long sys_work_interval_ctl(uint32_t operation, uint64_t work_interval_id, void* arg, uint64_t len);

#endif // LINUX_X86CODE_MEMFD_H
