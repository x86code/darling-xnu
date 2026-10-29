#ifndef LINUX_PID_SUSPEND_H
#define LINUX_PID_SUSPEND_H

long sys_pid_suspend(int pid);
long sys_pid_resume(int pid);

#endif
