#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsctl.h>

#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/access.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstat.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/bsdflags.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>


/*
 * x86Sim: fsctl (242) and ffsctl (245) were missing (ENOSYS). XNU passes them to the file system's VNOP_IOCTL, and
 * a request the file system doesn't know fails with ENOTTY. The ones the iOS simulator needs from APFS (it only runs
 * on APFS) are answered as APFS answers for a plain directory tree:
 * - _IOR('J', 74, uint64_t) (0x40084a4a): the id of the File Provider sync root enclosing the object, 0 for none.
 *   FileProvider's fpfs_fget_parent_syncroot() treats any error as fatal: the On My iPhone extension
 *   (LocalStorageFileProvider) then could not make an item for any file ("can't obtain VFSItem ... [78: Function not
 *   implemented]"), so Files could open no document.
 * - _IOW('J', 2, uint64_t) (0x80084a02): have APFS keep directory statistics for a directory (FileProvider's
 *   fpfs_pkg_enable_dirstat(), from fpfs_track_document() for every tracked item: the extension failed "can't obtain
 *   VFSItem ... [25: Inappropriate ioctl for device]"). Accepted and ignored. Reading the statistics
 *   (_IOWR('J', 32, 40 bytes), packages only) stays ENOTTY.
 * - FSIOC_CAS_BSDFLAGS (_IOWR('A', 20, struct fsioc_cas_bsdflags)): compare-and-swap of the chflags flags, kept in an
 *   extended attribute (helper/misc/bsdflags.h). As XNU: the actual flags are returned, and the new ones set only if
 *   they were the expected ones; it succeeds either way. FileProvider's libfssync sets UF_TRACKED with it.
 */
#define FSIOC_CAS_BSDFLAGS 0xc00c4114ul
struct fsioc_cas_bsdflags { uint32_t expected_flags, new_flags, actual_flags; };
#define APFSIOC_GET_PARENT_SYNCROOT 0x40084a4aul   // names ours; 'J' is APFS's ioctl group
#define APFSIOC_MAINTAIN_DIR_STATS  0x80084a02ul

static long fsctl_common(unsigned long cmd, void* data, const char* lpath)
{
	switch (cmd & 0xffffffffu)
	{
		case APFSIOC_MAINTAIN_DIR_STATS:
			return 0;
		case FSIOC_CAS_BSDFLAGS:
		{
			struct fsioc_cas_bsdflags* cas = data;
			if (!cas)
				return -EFAULT;
			uint32_t cur = x86sim_bsdflags_get(lpath, 0);
			if (cur == cas->expected_flags && cur != cas->new_flags)
			{
				long r = x86sim_bsdflags_set(lpath, cas->new_flags);
				if (r < 0)
					return errno_linux_to_bsd(r);
			}
			cas->actual_flags = cur;
			return 0;
		}
		case APFSIOC_GET_PARENT_SYNCROOT:
			if (!data)
				return -EFAULT;
			*(uint64_t*) data = 0;
			return 0;
		default:
		{
			// log each unknown request once (to stderr), as unsupported proc_info flavors are
			static unsigned long seen[16];
			unsigned int i;
			for (i = 0; i < 16 && seen[i] && seen[i] != cmd; i++);
			if (i < 16 && !seen[i])
			{
				seen[i] = cmd;
				__simple_printf("fsctl: unsupported request 0x%lx ('%c' %lu, %lu bytes)\n", cmd,
					(int) ((cmd >> 8) & 0xff), cmd & 0xff, (cmd >> 16) & 0x1fff);
			}
			return -ENOTTY;
		}
	}
}

long sys_fsctl(const char* path, unsigned long cmd, void* data, unsigned int options)
{
	long rv = sys_access(path, 0 /* F_OK */);
	if (rv < 0)
		return rv;
	struct vchroot_expand_args vc;
	vc.flags = VCHROOT_FOLLOW;
	vc.dfd = get_perthread_wd();
	strcpy(vc.path, path);
	rv = vchroot_expand(&vc);
	if (rv < 0)
		return errno_linux_to_bsd(rv);
	char buf[1100];
	const char* p = vc.path;
	if (vc.path[0] != '/' && vc.dfd != -100)
	{
		__simple_snprintf(buf, sizeof(buf), "/proc/self/fd/%d/%s", vc.dfd, vc.path);
		p = buf;
	}
	return fsctl_common(cmd, data, p);
}

long sys_ffsctl(int fd, unsigned long cmd, void* data, unsigned int options)
{
	uint64_t st[32];   // a Darwin struct stat64 (144 bytes); only whether fd is valid matters
	long rv = sys_fstat64(fd, (struct stat64*) st);
	if (rv < 0)
		return rv;
	char buf[32];
	return fsctl_common(cmd, data, x86sim_fd_path(fd, buf));
}
