#include <darling/emulation/xnu_syscall/bsd/impl/unistd/renameat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

extern char* strcpy(char* dst, const char* src);

long sys_renameat(int oldfd, const char* oldpath, int newfd, const char* newpath)
{
	int ret;
	struct vchroot_expand_args vc, vc2;

	vc.flags = 0;
	vc.dfd = atfd(oldfd);
	
	strcpy(vc.path, oldpath);

	vc2.flags = 0;
	vc2.dfd = atfd(newfd);

	strcpy(vc2.path, newpath);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_renameat, vc.dfd, vc.path, vc2.dfd, vc2.path);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return 0;
}

// x86Code: renameatx_np (atomic swap / exclusive rename) via Linux renameat2
#define DARWIN_RENAME_SECLUDE 0x00000001
#define DARWIN_RENAME_SWAP    0x00000002
#define DARWIN_RENAME_EXCL    0x00000004
// x86Code Speed 26: newer flags; searchd renames its index state with them and got ENOTSUP (Files: "Content
// Unavailable"). No symlink in the paths is followed (NOFOLLOW_ANY: the last component isn't, as rename never does);
// RESOLVE_BENEATH and SECLUDE (a hint) don't change a rename inside the prefix.
#define DARWIN_RENAME_NOFOLLOW_ANY    0x00000010
#define DARWIN_RENAME_RESOLVE_BENEATH 0x00000020
#define LINUX_RENAME_NOREPLACE 1
#define LINUX_RENAME_EXCHANGE  2

long sys_renameatx_np(int oldfd, const char* oldpath, int newfd, const char* newpath, unsigned int flags)
{
	int ret, lflags = 0;
	struct vchroot_expand_args vc, vc2;

	if (flags & ~(DARWIN_RENAME_SECLUDE | DARWIN_RENAME_SWAP | DARWIN_RENAME_EXCL | DARWIN_RENAME_NOFOLLOW_ANY |
			DARWIN_RENAME_RESOLVE_BENEATH))
		return -ENOTSUP;
	if ((flags & DARWIN_RENAME_SWAP) && (flags & DARWIN_RENAME_EXCL))
		return -EINVAL;
	if (flags & DARWIN_RENAME_SWAP)
		lflags = LINUX_RENAME_EXCHANGE;
	if (flags & DARWIN_RENAME_EXCL)
		lflags = LINUX_RENAME_NOREPLACE;

	vc.flags = 0;
	vc.dfd = atfd(oldfd);
	strcpy(vc.path, oldpath);

	vc2.flags = 0;
	vc2.dfd = atfd(newfd);
	strcpy(vc2.path, newpath);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_renameat2, vc.dfd, vc.path, vc2.dfd, vc2.path, lflags);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return 0;
}
