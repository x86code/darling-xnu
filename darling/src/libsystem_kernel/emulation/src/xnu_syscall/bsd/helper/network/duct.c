#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>

#include <sys/socket.h>

#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

unsigned long sockaddr_fixup_size_from_bsd(const void* bsd_sockaddr, int bsd_sockaddr_len) {
	return (((struct sockaddr_fixup*)bsd_sockaddr)->bsd_family == PF_LOCAL) ? sizeof(struct sockaddr_fixup) : bsd_sockaddr_len;
}

int sockaddr_fixup_from_bsd(struct sockaddr_fixup* out, const void* bsd_sockaddr, int bsd_sockaddr_len) {
	int ret = bsd_sockaddr_len;

	memcpy(out, bsd_sockaddr, bsd_sockaddr_len);

	out->linux_family = sfamily_bsd_to_linux(out->bsd_family);

	if (out->linux_family == LINUX_PF_LOCAL) {
		struct vchroot_expand_args vc;
		vc.flags = VCHROOT_FOLLOW;
		vc.dfd = get_perthread_wd();

		strcpy(vc.path, out->sun_path);

		ret = vchroot_expand(&vc);
		if (ret < 0)
			return errno_linux_to_bsd(ret);

		strncpy(out->sun_path, vc.path, sizeof(out->sun_path) - 1);
		out->sun_path[sizeof(out->sun_path) - 1] = '\0';
		ret = sizeof(*out) - sizeof(out->sun_path) + strlen(out->sun_path);
	}

	return ret;
}

// x86Sim: converted in a local copy and written back bounded by cap, the size of the caller's buffer (the kernel's
// length can exceed it: the address was truncated). The in-place version wrote a whole sun_path (strncpy pads all 104
// bytes) into whatever buffer the caller had, and strcpy'd a path an unnamed socket (a socketpair end: length 2) never
// had: RealityKit's getsockname on a socketpair into a small sockaddr smashed its stack (__stack_chk_fail).
// Returns the BSD length written (as XNU: min(address length, cap)), or a BSD errno.
int sockaddr_fixup_from_linux(struct sockaddr_fixup* out, const void* linux_sockaddr, int linux_sockaddr_len, int cap) {
	struct {
		struct sockaddr_fixup sa;
		char extra[16];  // Linux's sun_path is 108 bytes, BSD's 104
	} tmp;
	int ret, n = linux_sockaddr_len;

	if (cap < 0) cap = 0;
	if (n > cap) n = cap;
	if (n > (int)sizeof(tmp)) n = sizeof(tmp);
	if (n < 0) n = 0;
	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp, linux_sockaddr, n);
	ret = linux_sockaddr_len;

	tmp.sa.bsd_family = sfamily_linux_to_bsd(tmp.sa.linux_family);

	if (tmp.sa.bsd_family == PF_LOCAL) {
		int plen = n - (int)(sizeof(tmp.sa) - sizeof(tmp.sa.sun_path));
		if (plen > 0 && tmp.sa.sun_path[0] != '\0') {
			struct vchroot_unexpand_args vc;
			if (plen >= (int)sizeof(vc.path)) plen = sizeof(vc.path) - 1;
			memcpy(vc.path, tmp.sa.sun_path, plen);
			vc.path[plen] = '\0';

			ret = vchroot_unexpand(&vc);
			if (ret < 0)
				return errno_linux_to_bsd(ret);

			memset(tmp.sa.sun_path, 0, sizeof(tmp.sa.sun_path));
			strncpy(tmp.sa.sun_path, vc.path, sizeof(tmp.sa.sun_path) - 1);
			ret = sizeof(tmp.sa) - sizeof(tmp.sa.sun_path) + strlen(tmp.sa.sun_path) + 1;
		} else if (plen > 0) {
			ret = linux_sockaddr_len;  // abstract name: kept as is
		} else {
			ret = sizeof(tmp.sa) - sizeof(tmp.sa.sun_path);  // unnamed
		}
	}

	if (ret > (int)sizeof(tmp.sa)) ret = sizeof(tmp.sa);
	tmp.sa.bsd_length = ret;
	if (ret > cap) ret = cap;
	memcpy(out, &tmp, ret);
	return ret;
}
