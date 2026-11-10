#ifndef LINUX_X86SIM_MEMFD_H
#define LINUX_X86SIM_MEMFD_H

#include <stdint.h>

// x86Sim: Darling-private syscall 599, see x86sim_memfd.c
long sys_x86sim_memfd_for_region(uint64_t address, uint64_t size, uint64_t* out_offset, uint32_t* out_shared);

// x86Sim: Darling-private syscall 598, see x86sim_inotify.c
long sys_x86sim_inotify(uint32_t op, uint64_t a1, uint64_t a2, uint64_t a3);

// x86Sim: work_interval_ctl (BSD syscall 499), see x86sim_memfd.c
long sys_work_interval_ctl(uint32_t operation, uint64_t work_interval_id, void* arg, uint64_t len);

#endif // LINUX_X86SIM_MEMFD_H
