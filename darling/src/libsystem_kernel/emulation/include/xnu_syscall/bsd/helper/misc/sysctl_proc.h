#ifndef _SYSCTL_PROC_H
#define _SYSCTL_PROC_H

#include <stdbool.h>

// Utility functions for parsing Linux procfs /proc/XX/stat
bool read_string(const char* path, char* dst, int maxlen);
const char* next_stat_elem(char** buf);
void skip_stat_elems(char** buf, int count);
// x86Code: the Darwin process name (p_comm/pbi_name) of a Darling process
bool darling_proc_name(int pid, const char* comm, char* dst, int maxlen);

#endif // _SYSCTL_PROC_H
