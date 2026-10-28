#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makeport.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darlingserver/rpc.h>

// x86Code: fileports are kept by darlingserver (it holds a copy of the fd); this used the old LKM API and crashed
// (libxpc's xpc_fd_create, NSFileHandle over NSXPC: chronod's widget archive file promises)
long sys_fileport_makeport(int fd, int* port)
{
	uint32_t name = 0;
	int ret = dserver_rpc_fileport_makeport(fd, &name);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	*port = name;
	return 0;
}
