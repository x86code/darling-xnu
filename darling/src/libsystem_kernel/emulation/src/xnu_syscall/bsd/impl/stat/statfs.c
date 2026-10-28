#include <darling/emulation/xnu_syscall/bsd/impl/stat/statfs.h>

#include <stddef.h>
#include <sys/fcntl.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#undef strlcpy

extern char *strtok_r(char *str, const char *delim, char **saveptr);
extern __SIZE_TYPE__ strlcpy(char* dst, const char* src, __SIZE_TYPE__ size);
extern __SIZE_TYPE__ strlen(const char* str);
extern int strncmp(const char* s1, const char* s2, __SIZE_TYPE__ len);

long sys_statfs(const char* path, struct bsd_statfs* buf)
{
#ifdef __x86_64__
	return sys_statfs64(path, (struct bsd_statfs64*) buf);
#else
#	warning Not implemented
	return 0;
#endif
}

// x86Code: shared by statfs/fstatfs/getfsstat. /proc/self/mounts lists Linux paths (octal-escaped,
// e.g. "\040" for a space); Darling programs need them in the prefix view, as other syscalls see
// them ("/home" is "/Volumes/SystemRoot/home"). Before, f_mntonname was the Linux path, so the
// mount point did not exist for the caller: CFURL's NSURLVolumeURLKey failed, LaunchServices'
// FSNode could not get a volume identifier and lsd failed every registration with -43 (fnfErr).
void statfs_unescape_mount_path(char* s)
{
	char* d = s;
	while (*s)
	{
		if (s[0] == '\\' && s[1] >= '0' && s[1] <= '3' && s[2] >= '0' && s[2] <= '7' && s[3] >= '0' && s[3] <= '7')
		{
			*d++ = (char) (((s[1] - '0') << 6) | ((s[2] - '0') << 3) | (s[3] - '0'));
			s += 4;
		}
		else
			*d++ = *s++;
	}
	*d = 0;
}

void statfs_mount_path_to_darling(const char* linux_path, char* out, unsigned long outsize)
{
	struct vchroot_unexpand_args ua;
	strlcpy(ua.path, linux_path, sizeof(ua.path));
	vchroot_unexpand(&ua);
	int len = strlen(ua.path);
	if (len > 1 && ua.path[len - 1] == '/') // "/" -> "/Volumes/SystemRoot/"
		ua.path[len - 1] = 0;
	strlcpy(out, ua.path, outsize);
}


// x86Code: Darwin's mount sources are short BSD names ("/dev/disk3s5"); Linux's can be long device-mapper links
// ("/dev/mapper/luks-<uuid>", 53 characters). CacheDelete keeps a 32-byte BSD name and refused such a volume
// ("bsd_name_len (32) too short for ..."). A /dev/ source that is a symlink is reported as the device it names
// ("/dev/dm-0"), the kernel's own name for it.
void statfs_short_mntfrom(char* name, __SIZE_TYPE__ size)
{
	char target[256];
	long n;
	const char* base;

	if (strncmp(name, "/dev/", 5) != 0)
		return;
#ifdef __NR_readlink
	n = LINUX_SYSCALL(__NR_readlink, name, target, sizeof(target) - 1);
#else
	n = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, name, target, sizeof(target) - 1);
#endif
	if (n <= 0)
		return;
	target[n] = 0;
	base = target;
	for (const char* q = target; *q; q++)
		if (*q == '/')
			base = q + 1;
	if (*base == 0 || strlen(base) + 6 > size)
		return;
	strlcpy(name, "/dev/", size);
	strlcpy(name + 5, base, size - 5);
}


// x86Code: the type name of a local disk file system as a Mac reports it. The iOS simulator only runs on APFS, and
// code checks: FileProvider's FPVolumeFPFSSupported() takes a volume only when f_fstypename is "apfs"
// ("Non-eligible device ...: non-apfs"), so fileproviderd had no volume for the device's data, every provider
// (On My iPhone, Photos, iCloud Drive) stayed disabled and a domain without a volume asserted ("FPDDomain must have
// a volume attached"). Linux's local block file systems, and the overlay Darling's prefix is, say "apfs".
void statfs_mac_fstypename(char* name, __SIZE_TYPE__ size)
{
	static const char* const disk_fs[] = { "btrfs", "ext4", "ext3", "ext2", "xfs", "f2fs", "zfs", "bcachefs",
		"jfs", "reiserfs", "overlay", NULL };
	for (int i = 0; disk_fs[i]; i++) {
		if (strncmp(name, disk_fs[i], size) == 0) {
			strlcpy(name, "apfs", size);
			return;
		}
	}
}

// Fills mount point, fs type and source of the mount holding linux_path (a Linux path).
void statfs_fill_mount_info(const char* linux_path, struct bsd_statfs64* buf)
{
	struct simple_readline_buf rbuf;
	char line[1024];
	int max_len = -1;
	int fd;

	buf->f_mntonname[0] = 0;
	buf->f_fstypename[0] = 0;
	buf->f_mntfromname[0] = 0;

	fd = sys_open("/proc/self/mounts", O_RDONLY, 0);
	if (fd < 0)
		return;

	__simple_readline_init(&rbuf);

	while (__simple_readline(fd, &rbuf, line, sizeof(line)))
	{
		char* saveptr;
		char* mntfrom = strtok_r(line, " ", &saveptr);
		char* mnton = mntfrom ? strtok_r(NULL, " ", &saveptr) : NULL;
		char* fstype = mnton ? strtok_r(NULL, " ", &saveptr) : NULL;
		int len;

		if (fstype == NULL)
			continue;
		statfs_unescape_mount_path(mnton);
		statfs_unescape_mount_path(mntfrom);

		// The mount point must be a whole-component prefix ("/home" holds "/home/x", not "/homework").
		len = strlen(mnton);
		if (len == 1 && mnton[0] == '/')
			len = 0;
		if (strncmp(mnton, linux_path, len) != 0 || (linux_path[len] != '/' && linux_path[len] != 0))
			continue;
		// Later lines win on equal length (mounts stacked on the same point).
		if (len < max_len)
			continue;

		max_len = len;
		statfs_mount_path_to_darling(mnton, buf->f_mntonname, sizeof(buf->f_mntonname));
		strlcpy(buf->f_fstypename, fstype, sizeof(buf->f_fstypename));
		statfs_mac_fstypename(buf->f_fstypename, sizeof(buf->f_fstypename)); // x86Code
		strlcpy(buf->f_mntfromname, mntfrom, sizeof(buf->f_mntfromname));
		statfs_short_mntfrom(buf->f_mntfromname, sizeof(buf->f_mntfromname)); // x86Code
	}

	close_internal(fd);
}

long sys_statfs64(const char* path, struct bsd_statfs64* buf)
{
	int ret;
	struct linux_statfs64 lbuf;
	struct linux_stat lst;

	struct vchroot_expand_args vc;
	// x86Code: statfs follows symlinks; resolve them in the prefix view, not Linux's.
	vc.flags = VCHROOT_FOLLOW;
	vc.dfd = get_perthread_wd();

	strcpy(vc.path, path);
	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

#ifdef __NR_statfs64
	ret = LINUX_SYSCALL2(__NR_statfs64, vc.path, &lbuf);
#else
	ret = LINUX_SYSCALL2(__NR_statfs, vc.path, &lbuf);
#endif

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	statfs_linux_to_bsd64(&lbuf, buf);

	// x86Code: f_fsid = { st_dev, 0 } as on Darwin, matching ATTR_CMN_FSID/ATTR_CMN_DEVID from
	// getattrlist (callers compare them, and pass the fsid to fsgetpath/openbyid_np).
	if (LINUX_SYSCALL(__NR_stat, vc.path, &lst) == 0)
		buf->f_fsid = (unsigned int) lst.st_dev;

	statfs_fill_mount_info(vc.path, buf);
	return 0;
}
