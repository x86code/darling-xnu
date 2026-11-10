#include <darling/emulation/xnu_syscall/bsd/helper/ioctl/socket.h>

#include <sys/errno.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/sockio.h>
#include <netinet6/in6_var.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockextra.h>

int handle_socket(int fd, unsigned int cmd, void* arg, int* retval)
{
	switch (cmd)
	{
		// TODO: This has to be implemented for container with separate networking
		case SIOCGIFFLAGS:
		case SIOCSIFFLAGS:
		case SIOCAIFADDR: // set IPv4 address
		case SIOCAIFADDR_IN6: // set IPv6 address
			*retval = -ENOTSUP;
			return IOCTL_HANDLED;
		// x86Sim: interface functional type (sockextra.h)
		case BSD_SIOCGIFFUNCTIONALTYPE:
			*retval = sockextra_functional_type(fd, arg);
			return IOCTL_HANDLED;
		// x86Sim: SIOCGCONNINFO (sockextra_conninfo(), XNU's in_getconninfo()) is left unanswered (ENOTTY, as before):
		// with it answered, Network.framework's nw_endpoint_flow_connected() took
		// nw_endpoint_flow_override_connected_on_path() and aborted on a recursive os_unfair_lock in
		// nw_endpoint_flow_copy_path() (geod and NewsTodayIntents in a loop), with the bound interface or 0 alike.
	}
	return IOCTL_PASS;
}
