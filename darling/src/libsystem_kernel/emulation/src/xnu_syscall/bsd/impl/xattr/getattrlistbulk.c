#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getattrlistbulk.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getattrlistat.h>

/*
 * x86Sim: getattrlistbulk(dirfd, alist, buf, size, options) on top of getattrlistat:
 * one attribute record per directory entry ("." and ".." skipped), each padded to
 * 8 bytes as XNU does. Returns the number of records, 0 at the end. An entry that
 * does not fit is left for the next call (the directory offset is moved back).
 * Like XNU, ATTR_CMN_RETURNED_ATTRS must be requested.
 */

#define ATTR_CMN_RETURNED_ATTRS 0x80000000
#define FSOPT_NOFOLLOW          0x00000001
#define FSOPT_REPORT_FULLSIZE   0x00000004
#define LINUX_SEEK_SET 0

long sys_getattrlistbulk(int dirfd, struct xnu_attrlist* alist, void* attributeBuffer, __SIZE_TYPE__ bufferSize, uint64_t options)
{
	char dents[4096];
	char* out = attributeBuffer;
	__SIZE_TYPE__ used = 0;
	long count = 0;
	int n;

	if (alist == NULL || attributeBuffer == NULL)
		return -EFAULT;
	if (!(alist->commonattr & ATTR_CMN_RETURNED_ATTRS))
		return -EINVAL;

	for (;;)
	{
		long long start = LINUX_SYSCALL(__NR_lseek, dirfd, 0, 1 /* SEEK_CUR */);
		n = LINUX_SYSCALL(__NR_getdents64, dirfd, dents, sizeof(dents));
		if (n < 0)
			return count > 0 ? count : errno_linux_to_bsd(n);
		if (n == 0)
			return count;

		long long resume = start;
		for (char* iter = dents; iter < dents + n; iter += ((struct linux_dirent64*) iter)->d_reclen)
		{
			struct linux_dirent64* d = (struct linux_dirent64*) iter;
			const char* name = d->d_name;

			if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
			{
				resume = d->d_off;
				continue;
			}

			__SIZE_TYPE__ room = bufferSize - used;
			long rv = room >= 4 ? sys_getattrlistat(dirfd, name, alist, out + used, room,
				options | FSOPT_NOFOLLOW | FSOPT_REPORT_FULLSIZE) : -ENOMEM;
			uint32_t need = rv == 0 ? *(uint32_t*) (out + used) : 0;
			uint32_t padded = (need + 7) & ~7u;

			if (rv == 0 && padded <= room)
			{
				*(uint32_t*) (out + used) = padded;
				used += padded;
				count++;
				resume = d->d_off;
				continue;
			}
			if (rv != 0 && rv != -ENOMEM && rv != -ERANGE)
			{
				// entry vanished or cannot be described: skip it
				resume = d->d_off;
				continue;
			}

			// does not fit: retry this entry next time
			LINUX_SYSCALL(__NR_lseek, dirfd, resume, LINUX_SEEK_SET);
			if (count == 0)
				return -ENOMEM; // buffer too small for even one entry (XNU: ERANGE?)
			return count;
		}
	}
}
