#include <darling/emulation/xnu_syscall/bsd/impl/stat/getfsstat.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/statfs.h>

#include <stddef.h>
#include <sys/fcntl.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

extern char *strtok_r(char *str, const char *delim, char **saveptr);
extern unsigned long strlcpy(char* dst, const char* src, unsigned long size);

long sys_getfsstat(struct bsd_statfs* buf, int bufsize, int flags)
{
#ifdef __x86_64__
	return sys_getfsstat64((struct bsd_statfs64*) buf, bufsize, flags);
#else
#	warning Not implemented
	return 0;
#endif
}

// x86Sim: whether some /proc/self/mounts mount point has st_dev dev.
static int getfsstat_dev_is_mount(unsigned long long dev)
{
	struct simple_readline_buf rbuf;
	char line[1024];
	int found = 0;
	int fd = sys_open("/proc/self/mounts", O_RDONLY, 0);
	if (fd < 0)
		return 0;
	__simple_readline_init(&rbuf);
	while (__simple_readline(fd, &rbuf, line, sizeof(line)))
	{
		char* saveptr;
		char* mnton = strtok_r(line, " ", &saveptr) ? strtok_r(NULL, " ", &saveptr) : NULL;
		struct linux_stat st;
		if (mnton == NULL)
			continue;
		statfs_unescape_mount_path(mnton);
		if (LINUX_SYSCALL(__NR_stat, mnton, &st) == 0 && st.st_dev == dev)
		{
			found = 1;
			break;
		}
	}
	close_internal(fd);
	return found;
}

long sys_getfsstat64(struct bsd_statfs64* buf, int bufsize, int flags)
{
	int fd;
	struct simple_readline_buf rbuf;
	char line[512];
	int count = 0;

	fd = sys_open("/proc/self/mounts", O_RDONLY, 0);
	if (fd < 0)
		return errno_linux_to_bsd(fd);
	
	__simple_readline_init(&rbuf);

	while (__simple_readline(fd, &rbuf, line, sizeof(line)))
	{
		char* p;
		char* saveptr;
		struct linux_statfs64 lbuf;

		if (buf != NULL)
		{
			if (bufsize < sizeof(struct bsd_statfs64) * (count+1))
				break;

			p = strtok_r(line, " ", &saveptr);
			if (p == NULL)
				continue;

			strlcpy(buf[count].f_mntfromname, p, sizeof(buf[count].f_mntfromname));
			statfs_short_mntfrom(buf[count].f_mntfromname, sizeof(buf[count].f_mntfromname)); // x86Sim

			p = strtok_r(NULL, " ", &saveptr);
			if (p == NULL)
				continue;

			// x86Sim: unescape ("\\040") for the Linux statfs below; reported in the prefix view after it.
			statfs_unescape_mount_path(p);
			strlcpy(buf[count].f_mntonname, p, sizeof(buf[count].f_mntonname));

			p = strtok_r(NULL, " ", &saveptr);
			if (p == NULL)
				continue;

			strlcpy(buf[count].f_fstypename, p, sizeof(buf[count].f_fstypename));
			statfs_mac_fstypename(buf[count].f_fstypename, sizeof(buf[count].f_fstypename)); // x86Sim

#ifdef __NR_statfs64
			if (LINUX_SYSCALL2(__NR_statfs64, (char*)buf[count].f_mntonname, &lbuf) < 0)
#else
			if (LINUX_SYSCALL2(__NR_statfs, (char*)buf[count].f_mntonname, &lbuf) < 0)
#endif
				continue;

			statfs_linux_to_bsd64(&lbuf, &buf[count]);
			{
				// x86Sim: f_fsid = { st_dev, 0 } as in statfs/fstatfs: CFURL finds a file's volume
				// (NSURLVolumeURLKey) by matching its fsid against this table.
				struct linux_stat lst;
				if (LINUX_SYSCALL(__NR_stat, (char*)buf[count].f_mntonname, &lst) == 0)
					buf[count].f_fsid = (unsigned int) lst.st_dev;
			}
			{
				char lpath[1024];
				strlcpy(lpath, buf[count].f_mntonname, sizeof(lpath));
				statfs_mount_path_to_darling(lpath, buf[count].f_mntonname, sizeof(buf[count].f_mntonname));
			}
		}

		count++;
	}

	close_internal(fd);

	// x86Sim: then the unmounted subvolumes (statfs.c, statfs_subvol_root) the guest uses, so a
	// file's fsid {st_dev,0} there matches an entry, with the f_mntonname statfs returns for it.
	{
		unsigned long long seen[17];
		int nseen = 0;
		char root[1024];
		unsigned long long dev;

		for (int i = 0; statfs_extra_root(i, root, sizeof(root), &dev) == 0; i++)
		{
			struct linux_statfs64 lbuf;
			int dup = 0;

			if (dev == 0)
				continue;
			for (int j = 0; j < nseen; j++)
				dup |= seen[j] == dev;
			if (dup || getfsstat_dev_is_mount(dev))
				continue;
			if (nseen < (int)(sizeof(seen) / sizeof(seen[0])))
				seen[nseen++] = dev;

			if (buf != NULL)
			{
				if (bufsize < sizeof(struct bsd_statfs64) * (count+1))
					break;
#ifdef __NR_statfs64
				if (LINUX_SYSCALL2(__NR_statfs64, root, &lbuf) < 0)
#else
				if (LINUX_SYSCALL2(__NR_statfs, root, &lbuf) < 0)
#endif
					continue;
				statfs_linux_to_bsd64(&lbuf, &buf[count]);
				// Source and type of the mount it is reached through; dev 0: no subvolume lookup.
				statfs_fill_mount_info(root, 0, &buf[count]);
				buf[count].f_fsid = (unsigned int) dev;
				statfs_mount_path_to_darling(root, buf[count].f_mntonname, sizeof(buf[count].f_mntonname));
			}
			count++;
		}
	}
	return count;
}
