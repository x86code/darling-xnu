#ifndef LINUX_THREAD_SELFCOUNTS_H
#define LINUX_THREAD_SELFCOUNTS_H

/* SYS_thread_selfcounts (186): type 1 writes uint64_t[2] {instrs, cycles}. */
long sys_thread_selfcounts(int type, void* buf, unsigned long nbytes);

#endif /* LINUX_THREAD_SELFCOUNTS_H */
