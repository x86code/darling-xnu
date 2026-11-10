#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makefd.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darlingserver/rpc.h>

// x86Sim: see fileport_makeport.c
long sys_fileport_makefd(int port)
{
	int fd = -1;
	int ret = dserver_rpc_fileport_makefd(port, &fd);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return fd;
}
