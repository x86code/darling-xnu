#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/bsdflags.h> // x86Code
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstatfs.h>
#include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

/*
 * getattrlist(2) family. x86Code: rewritten from a 4-attribute version that failed
 * everything else with EINVAL (Apple's realpath(), NSURL resource values and
 * containermanagerd all use the common attributes).
 *
 * Follows XNU: attributes are packed in bitmap order (common, volume, directory,
 * file, then extended common with FSOPT_ATTR_CMN_EXTENDED); variable-length ones are
 * attrreference_t pointing into the area after the fixed part; directory attributes
 * only apply to directories and file attributes only to other objects. Attributes
 * that cannot be provided are left out and reported through ATTR_CMN_RETURNED_ATTRS,
 * or packed as zero with FSOPT_PACK_INVAL_ATTRS. Volume attributes (ATTR_VOL_INFO)
 * describe the file system holding the object, from statfs.
 */

#define ATTR_BIT_MAP_COUNT 5

#define FSOPT_NOFOLLOW          0x00000001
#define FSOPT_REPORT_FULLSIZE   0x00000004
#define FSOPT_PACK_INVAL_ATTRS  0x00000008
#define FSOPT_ATTR_CMN_EXTENDED 0x00000020

#define ATTR_CMN_NAME           0x00000001
#define ATTR_CMN_DEVID          0x00000002
#define ATTR_CMN_FSID           0x00000004
#define ATTR_CMN_OBJTYPE        0x00000008
#define ATTR_CMN_OBJTAG         0x00000010
#define ATTR_CMN_OBJID          0x00000020
#define ATTR_CMN_OBJPERMANENTID 0x00000040
#define ATTR_CMN_PAROBJID       0x00000080
#define ATTR_CMN_SCRIPT         0x00000100
#define ATTR_CMN_CRTIME         0x00000200
#define ATTR_CMN_MODTIME        0x00000400
#define ATTR_CMN_CHGTIME        0x00000800
#define ATTR_CMN_ACCTIME        0x00001000
#define ATTR_CMN_BKUPTIME       0x00002000
#define ATTR_CMN_FNDRINFO       0x00004000
#define ATTR_CMN_OWNERID        0x00008000
#define ATTR_CMN_GRPID          0x00010000
#define ATTR_CMN_ACCESSMASK     0x00020000
#define ATTR_CMN_FLAGS          0x00040000
#define ATTR_CMN_GEN_COUNT      0x00080000
#define ATTR_CMN_DOCUMENT_ID    0x00100000
#define ATTR_CMN_USERACCESS     0x00200000
#define ATTR_CMN_EXTENDED_SECURITY 0x00400000
#define ATTR_CMN_UUID           0x00800000
#define ATTR_CMN_GRPUUID        0x01000000
#define ATTR_CMN_FILEID         0x02000000
#define ATTR_CMN_PARENTID       0x04000000
#define ATTR_CMN_FULLPATH       0x08000000
#define ATTR_CMN_ADDEDTIME      0x10000000
#define ATTR_CMN_ERROR          0x20000000
#define ATTR_CMN_DATA_PROTECT_FLAGS 0x40000000
#define ATTR_CMN_RETURNED_ATTRS 0x80000000
#define ATTR_CMN_VALIDMASK      0xFFFFFFFF

#define ATTR_VOL_FSTYPE         0x00000001
#define ATTR_VOL_SIGNATURE      0x00000002
#define ATTR_VOL_SIZE           0x00000004
#define ATTR_VOL_SPACEFREE      0x00000008
#define ATTR_VOL_SPACEAVAIL     0x00000010
#define ATTR_VOL_MINALLOCATION  0x00000020
#define ATTR_VOL_ALLOCATIONCLUMP 0x00000040
#define ATTR_VOL_IOBLOCKSIZE    0x00000080
#define ATTR_VOL_OBJCOUNT       0x00000100
#define ATTR_VOL_FILECOUNT      0x00000200
#define ATTR_VOL_DIRCOUNT       0x00000400
#define ATTR_VOL_MAXOBJCOUNT    0x00000800
#define ATTR_VOL_MOUNTPOINT     0x00001000
#define ATTR_VOL_NAME           0x00002000
#define ATTR_VOL_MOUNTFLAGS     0x00004000
#define ATTR_VOL_MOUNTEDDEVICE  0x00008000
#define ATTR_VOL_ENCODINGSUSED  0x00010000
#define ATTR_VOL_CAPABILITIES   0x00020000
#define ATTR_VOL_UUID           0x00040000
// x86Code: the newer volume attributes (XNU 8792+). installd's -[MIFileManager copyVolumeInfo:forURL:error:] asks
// for ATTR_VOL_MOUNTPOINT|ATTR_VOL_UUID|ATTR_VOL_FSTYPENAME; EINVAL failed every app install (x86sim install).
#define ATTR_VOL_MOUNTEXTFLAGS  0x00080000
#define ATTR_VOL_FSTYPENAME     0x00100000
#define ATTR_VOL_FSSUBTYPE      0x00200000
#define ATTR_VOL_OWNER          0x00400000
#define ATTR_VOL_SPACEUSED      0x00800000
#define ATTR_VOL_QUOTA_SIZE     0x10000000
#define ATTR_VOL_RESERVED_SIZE  0x20000000
#define ATTR_VOL_ATTRIBUTES     0x40000000
#define ATTR_VOL_INFO           0x80000000
#define ATTR_VOL_VALIDMASK      0xF0FFFFFF // x86Code: with the attributes above

// vol_capabilities_attr_t
#define VOL_CAPABILITIES_FORMAT     0
#define VOL_CAPABILITIES_INTERFACES 1
#define VOL_CAP_FMT_PERSISTENTOBJECTIDS 0x00000001
#define VOL_CAP_FMT_PATH_FROM_ID 0x00004000
#define VOL_CAP_FMT_SYMBOLICLINKS   0x00000002
#define VOL_CAP_FMT_HARDLINKS       0x00000004
#define VOL_CAP_FMT_SPARSE_FILES    0x00000040
#define VOL_CAP_FMT_CASE_SENSITIVE  0x00000100
#define VOL_CAP_FMT_CASE_PRESERVING 0x00000200
#define VOL_CAP_FMT_FAST_STATFS     0x00000400
#define VOL_CAP_FMT_2TB_FILESIZE    0x00000800
#define VOL_CAP_FMT_64BIT_OBJECT_IDS 0x00020000
#define VOL_CAP_INT_ATTRLIST        0x00000002
#define VOL_CAP_INT_ADVLOCK         0x00000100
#define VOL_CAP_INT_FLOCK           0x00000200
#define VOL_CAP_INT_USERACCESS      0x00000800
#define VOL_CAP_INT_EXTENDED_ATTR   0x00004000
#define VOL_CAP_INT_RENAME_SWAP     0x00040000
#define VOL_CAP_INT_RENAME_EXCL     0x00080000

#define ATTR_DIR_LINKCOUNT      0x00000001
#define ATTR_DIR_ENTRYCOUNT     0x00000002
#define ATTR_DIR_MOUNTSTATUS    0x00000004
#define ATTR_DIR_ALLOCSIZE      0x00000008
#define ATTR_DIR_IOBLOCKSIZE    0x00000010
#define ATTR_DIR_DATALENGTH     0x00000020
#define ATTR_DIR_VALIDMASK      0x0000003F

#define ATTR_FILE_LINKCOUNT     0x00000001
#define ATTR_FILE_TOTALSIZE     0x00000002
#define ATTR_FILE_ALLOCSIZE     0x00000004
#define ATTR_FILE_IOBLOCKSIZE   0x00000008
#define ATTR_FILE_CLUMPSIZE     0x00000010
#define ATTR_FILE_DEVTYPE       0x00000020
#define ATTR_FILE_FILETYPE      0x00000040
#define ATTR_FILE_FORKCOUNT     0x00000080
#define ATTR_FILE_FORKLIST      0x00000100
#define ATTR_FILE_DATALENGTH    0x00000200
#define ATTR_FILE_DATAALLOCSIZE 0x00000400
#define ATTR_FILE_DATAEXTENTS   0x00000800
#define ATTR_FILE_RSRCLENGTH    0x00001000
#define ATTR_FILE_RSRCALLOCSIZE 0x00002000
#define ATTR_FILE_VALIDMASK     0x37FF

#define ATTR_CMNEXT_RELPATH     0x00000004
#define ATTR_CMNEXT_PRIVATESIZE 0x00000008
#define ATTR_CMNEXT_LINKID      0x00000010
#define ATTR_CMNEXT_NOFIRMLINKPATH 0x00000020
#define ATTR_CMNEXT_REALDEVID   0x00000040
#define ATTR_CMNEXT_REALFSID    0x00000080
#define ATTR_CMNEXT_CLONEID     0x00000100
#define ATTR_CMNEXT_EXT_FLAGS   0x00000200
#define ATTR_CMNEXT_RECURSIVE_GENCOUNT 0x00000400
#define ATTR_CMNEXT_ATTRIBUTION_TAG 0x00000800
#define ATTR_CMNEXT_CLONE_REFCNT 0x00001000
#define ATTR_CMNEXT_VALIDMASK   0x00001FFC

#define ATTR_FORK_VALIDMASK     0x00000003

// x86Code: Darwin xattr names live in Linux's "user." namespace (xattr_names.h)
#define XATTR_FINDER_INFO "user.com.apple.FinderInfo"
#define XATTR_RESOURCE_FORK "user.com.apple.ResourceFork"

#define VT_HFS 16

// fsobj_type_t
#define VNON 0
#define VREG 1
#define VDIR 2
#define VBLK 3
#define VCHR 4
#define VLNK 5
#define VSOCK 6
#define VFIFO 7

#ifndef LINUX_O_PATH
#define LINUX_O_PATH 010000000
#endif

#define GETATTR_PATH_MAX 1024

#define min(a,b) (((a) < (b)) ? (a) : (b))

extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern void *memset(void *s, int c, __SIZE_TYPE__ n);
extern char *strcpy(char *dest, const char *src);
extern __SIZE_TYPE__ strlen(const char *s);
extern char *strrchr(const char *s, int c);

#ifndef GETATTRLIST_HELPERS
#define GETATTRLIST_HELPERS

struct getattr_packer
{
	char* fixed;       // next fixed-size slot
	char* var;         // next variable-length slot
	char* end;         // end of our buffer
};

static void getattr_put(struct getattr_packer* p, const void* data, __SIZE_TYPE__ size)
{
	if (p->fixed + size <= p->end)
		memcpy(p->fixed, data, size);
	p->fixed += size;
}

static void getattr_put_u32(struct getattr_packer* p, uint32_t v) { getattr_put(p, &v, 4); }
static void getattr_put_u64(struct getattr_packer* p, uint64_t v) { getattr_put(p, &v, 8); }

static void getattr_put_ts(struct getattr_packer* p, long sec, long nsec)
{
	int64_t ts[2] = { sec, nsec };
	getattr_put(p, ts, sizeof(ts));
}

// attrreference_t { int32 offset (from the reference itself), uint32 length incl. NUL }
static void getattr_put_ref(struct getattr_packer* p, const char* str)
{
	uint32_t len = strlen(str) + 1;
	int32_t ref[2];

	ref[0] = (int32_t) (p->var - p->fixed);
	ref[1] = len;
	getattr_put(p, ref, sizeof(ref));
	if (p->var + len <= p->end)
		memcpy(p->var, str, len);
	p->var += (len + 3) & ~3;
}

static uint32_t getattr_objtype(uint32_t mode)
{
	switch (mode & S_IFMT)
	{
		case S_IFREG: return VREG;
		case S_IFDIR: return VDIR;
		case S_IFBLK: return VBLK;
		case S_IFCHR: return VCHR;
		case S_IFLNK: return VLNK;
		case S_IFSOCK: return VSOCK;
		case S_IFIFO: return VFIFO;
	}
	return VNON;
}

static uint32_t getattr_count_entries(int dirfd)
{
	char buf[1024];
	uint32_t count = 0;
	int rv;

	while ((rv = LINUX_SYSCALL(__NR_getdents64, dirfd, buf, sizeof(buf))) > 0)
	{
		for (char* iter = buf; iter < buf + rv; iter += ((struct linux_dirent64*)iter)->d_reclen)
		{
			const char* name = ((struct linux_dirent64*)iter)->d_name;
			// XNU does not count "." and ".."
			if (!(name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))))
				count++;
		}
	}
	return count;
}

#endif // GETATTRLIST_HELPERS

long
FUNC_NAME(int fd,

#if HAS_PATH
const char* path,
#endif

struct xnu_attrlist* alist, void *attributeBuffer, __SIZE_TYPE__ bufferSize, unsigned long options)
{
	int rv;
	struct linux_stat lst;
	struct stat64 st;
	int objfd = -1; // O_PATH descriptor of the object, for its path and directory contents
	char fullpath[GETATTR_PATH_MAX];
	const char* name;
	uint32_t common, vol = 0, dir = 0, file = 0, cmnext = 0;
	struct bsd_statfs64 sfs;
	uint32_t returned[ATTR_BIT_MAP_COUNT] = { 0 };
	int isdir;

	if (!alist || !attributeBuffer)
		return -EFAULT;
	if (alist->bitmapcount != ATTR_BIT_MAP_COUNT)
		return -EINVAL;

	// Volume attributes: XNU's getattrlist does not require ATTR_VOL_INFO (only setattrlist does; the man page
	// asks for it). x86Code: FileProvider's -[NSURL fp_volumeUUID] asks for ATTR_VOL_UUID alone, and every EINVAL
	// left fileproviderd without volume UUIDs for its domains (Files could not open a document). XNU also uses
	// the volume's root for a non-root object; we describe the volume holding any object.
	if (alist->volattr & ~ATTR_VOL_VALIDMASK)
		return -EINVAL;
	vol = alist->volattr & ~ATTR_VOL_INFO;
	if ((alist->dirattr & ~ATTR_DIR_VALIDMASK) || (alist->fileattr & ~ATTR_FILE_VALIDMASK))
		return -EINVAL;
	if (options & FSOPT_ATTR_CMN_EXTENDED)
	{
		if (alist->forkattr & ~ATTR_CMNEXT_VALIDMASK)
			return -EINVAL;
		cmnext = alist->forkattr;
	}
	else if (alist->forkattr != 0)
		return -EINVAL; // fork attributes are obsolete

#if HAS_PATH
	if (!path)
		return -EFAULT;

	struct vchroot_expand_args vc;
	vc.flags = (options & FSOPT_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	strcpy(vc.path, path);
	rv = vchroot_expand(&vc);
	if (rv < 0)
		return errno_linux_to_bsd(rv);

	rv = LINUX_SYSCALL(__NR_newfstatat, vc.dfd, vc.path, &lst,
		(options & FSOPT_NOFOLLOW) ? LINUX_AT_SYMLINK_NOFOLLOW : 0);
	if (rv < 0)
		return errno_linux_to_bsd(rv);

	objfd = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path,
		LINUX_O_PATH | LINUX_O_CLOEXEC | ((options & FSOPT_NOFOLLOW) ? LINUX_O_NOFOLLOW : 0), 0);
#else
	rv = LINUX_SYSCALL(__NR_fstat, fd, &lst);
	if (rv < 0)
		return errno_linux_to_bsd(rv);
	objfd = sys_dup(fd);
#endif

	stat_linux_to_bsd64(&lst, &st);
	isdir = S_ISDIR(st.st_mode);
	if (objfd >= 0 && !S_ISLNK(st.st_mode)) // x86Code: chflags flags (helper/misc/bsdflags.h)
		st.st_flags = x86code_bsdflags_get_fd(objfd);
	if (isdir)
		dir = alist->dirattr;
	else
		file = alist->fileattr;

	fullpath[0] = 0;
	if (objfd >= 0 && fdpath(objfd, fullpath, sizeof(fullpath)) < 0)
		fullpath[0] = 0;
	name = strrchr(fullpath, '/');
	name = (name && name[1]) ? name + 1 : (fullpath[0] ? fullpath : "");

#if HAS_PATH
	// The object's own name is the last component asked for: the resolved path can
	// differ where Darling maps directories (e.g. /Volumes/SystemRoot is the Linux /,
	// whose resolved name would be "/"). realpath() builds paths from these names.
	char lastcomp[GETATTR_PATH_MAX];
	{
		__SIZE_TYPE__ len = strlen(path);
		while (len > 1 && path[len - 1] == '/')
			len--;
		__SIZE_TYPE__ start = len;
		while (start > 0 && path[start - 1] != '/')
			start--;
		if (len - start < sizeof(lastcomp) && len > start)
		{
			memcpy(lastcomp, path + start, len - start);
			lastcomp[len - start] = 0;
			if (!(lastcomp[0] == '.' && (lastcomp[1] == 0 || (lastcomp[1] == '.' && lastcomp[2] == 0))))
				name = lastcomp;
		}
	}
#endif

	// What we can return: everything except the attributes below
	// x86Code: DATA_PROTECT_FLAGS (class 0) and CMNEXT_CLONEID are returned as APFS does: CoreFoundation's
	// _kCFURLFileIDKey is NULL unless every attribute of its request comes back, and LaunchServices'
	// -[FSNode checkResourceIsReachableAndReturnError:] needs it (no executable info, platform 0, -10814)
	common = alist->commonattr & ~(ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID
		| ATTR_CMN_ERROR);
	if (!fullpath[0])
		common &= ~ATTR_CMN_FULLPATH;
	cmnext &= ATTR_CMNEXT_LINKID | ATTR_CMNEXT_NOFIRMLINKPATH | ATTR_CMNEXT_REALDEVID
		| ATTR_CMNEXT_REALFSID | ATTR_CMNEXT_PRIVATESIZE | ATTR_CMNEXT_EXT_FLAGS | ATTR_CMNEXT_CLONEID;
	if (!fullpath[0])
		cmnext &= ~ATTR_CMNEXT_NOFIRMLINKPATH;

	memset(&sfs, 0, sizeof(sfs));
	if (vol && (objfd < 0 || sys_fstatfs64(objfd, &sfs) < 0))
		vol = 0;

	returned[0] = common;
	returned[1] = vol ? (vol | ATTR_VOL_INFO) : 0;
	returned[2] = dir;
	returned[3] = file & ~ATTR_FILE_DATAEXTENTS;
	returned[4] = cmnext;
	if (!isdir)
		file &= ~ATTR_FILE_DATAEXTENTS;

	if (options & FSOPT_PACK_INVAL_ATTRS)
	{
		// pack every requested attribute; the ones we lack as zero / empty
		common = alist->commonattr;
		vol = alist->volattr & ~ATTR_VOL_INFO;
		// x86Code: as XNU (vfs_attr_pack_internal), even here directory attributes are packed for directories
		// only and file attributes for everything else: packing both shifted a file's attributes by the directory
		// ones (FileProvider read a 491 KB file's ATTR_FILE_ALLOCSIZE as 491520 << 32, "2.11 PB" in Preview)
		dir = isdir ? alist->dirattr : 0;
		file = isdir ? 0 : alist->fileattr;
		cmnext = (options & FSOPT_ATTR_CMN_EXTENDED) ? alist->forkattr : 0;
	}

	// Generous upper bound for the fixed part plus variable data
	__SIZE_TYPE__ bufsize = 4 + 32 * 16 + 2 * (GETATTR_PATH_MAX + 4) + 64;
	char* ourBuffer = (char*) __builtin_alloca(bufsize);
	memset(ourBuffer, 0, bufsize);

	// First pass: size of the fixed part, so variable data can follow it
	__SIZE_TYPE__ fixedSize = 4;
	{
		static const uint8_t cmn_sizes[32] = {
			8, 4, 8, 4, 4, 8, 8, 8, 4, 16, 16, 16, 16, 16, 32, 4,
			4, 4, 4, 4, 4, 4, 8, 16, 16, 8, 8, 8, 16, 4, 4, 20 };
		static const uint8_t vol_sizes[32] = {
			4, 4, 8, 8, 8, 8, 8, 4, 4, 4, 4, 4, 8, 8, 4, 8,
			8, 32, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 40, 0 };
		static const uint8_t dir_sizes[6] = { 4, 4, 4, 8, 4, 8 };
		static const uint8_t file_sizes[14] = { 4, 8, 8, 4, 4, 4, 4, 4, 8, 8, 8, 0, 8, 8 };
		static const uint8_t ext_sizes[13] = { 0, 0, 8, 8, 8, 8, 4, 8, 8, 8, 8, 8, 4 };
		for (int i = 0; i < 32; i++)
			if (common & (1u << i)) fixedSize += cmn_sizes[i];
		for (int i = 0; i < 32; i++)
			if (vol & (1u << i)) fixedSize += vol_sizes[i];
		for (int i = 0; i < 6; i++)
			if (dir & (1u << i)) fixedSize += dir_sizes[i];
		for (int i = 0; i < 14; i++)
			if (file & (1u << i)) fixedSize += file_sizes[i];
		for (int i = 0; i < 13; i++)
			if (cmnext & (1u << i)) fixedSize += ext_sizes[i];
	}

	struct getattr_packer p = {
		.fixed = ourBuffer + 4,
		.var = ourBuffer + fixedSize,
		.end = ourBuffer + bufsize,
	};

	uint64_t devid = st.st_dev;
	uint64_t fileid = st.st_ino;
	uint64_t parentid = 0;
	uint32_t mntstatus = 0; // x86Code: DIR_MNTSTATUS_MNTPOINT for the root of a mounted file system
	{
		struct linux_stat pst;
		int pfd = (objfd >= 0 && isdir) ? LINUX_SYSCALL(__NR_openat, objfd, "..", LINUX_O_PATH | LINUX_O_CLOEXEC, 0) : -1;
		if (pfd >= 0)
		{
			// x86Code: the root of a mounted file system: its ".." is on another device, and the inode number
			// alone can't say which one (every btrfs subvolume root is inode 256, so /home's parent "/" had
			// /home's own ID and CoreServicesInternal's walk to the root never ended). Like a root, it is
			// its own parent.
			if (LINUX_SYSCALL(__NR_fstat, pfd, &pst) == 0)
			{
				parentid = pst.st_dev == lst.st_dev ? pst.st_ino : lst.st_ino;
				if (pst.st_dev != lst.st_dev || pst.st_ino == lst.st_ino)
					mntstatus = 1; // DIR_MNTSTATUS_MNTPOINT: CoreServicesInternal stops its walk to the volume root here
			}
			close_internal(pfd);
		}
		else if (objfd >= 0)
		{
			// x86Code: ".." of a non-directory fails (ENOTDIR), so ATTR_CMN_PARENTID was 0 for every file;
			// CoreServicesInternal then has no file ID (_kCFURLFileIDKey NULL) and LaunchServices cannot make
			// an FSNode for an executable. Use the directory of the fd's Linux path.
			char procpath[32], lpath[GETATTR_PATH_MAX];
			__simple_sprintf(procpath, "/proc/self/fd/%d", objfd);
			long n = LINUX_SYSCALL(__NR_readlink, procpath, lpath, sizeof(lpath) - 1);
			if (n > 0)
			{
				lpath[n] = 0;
				char* slash = strrchr(lpath, '/');
				if (slash == lpath)
					slash[1] = 0;
				else if (slash)
					*slash = 0;
				if (slash && LINUX_SYSCALL(__NR_newfstatat, LINUX_AT_FDCWD, lpath, &pst, 0) == 0)
					parentid = pst.st_ino;
			}
		}
	}

	// x86Code: the prefix root is the top of the tree: its parent is itself. Its Linux ".." is the directory that
	// holds the prefix (~), which the prefix sees as /Volumes/SystemRoot/home/<user>; CoreServicesInternal walks
	// parent IDs up to the root, so it went root -> /Volumes/SystemRoot/home/... -> /Volumes -> root for ever
	// (lsd spun at 100% CPU and never wrote its database when it was rebuilt).
	if (fullpath[0] == '/' && fullpath[1] == 0)
	{
		parentid = fileid;
		mntstatus = 1;
	}

	// x86Code: remember the path of IDs we hand out for fsgetpath
	if (fullpath[0] && (common & (ATTR_CMN_FILEID | ATTR_CMN_OBJID) || cmnext & ATTR_CMNEXT_LINKID))
		fsgetpath_remember((uint32_t) devid, fileid, fullpath);

	if (common & ATTR_CMN_RETURNED_ATTRS)
		getattr_put(&p, returned, sizeof(returned));
	if (common & ATTR_CMN_NAME)
		getattr_put_ref(&p, name);
	if (common & ATTR_CMN_DEVID)
		getattr_put_u32(&p, (uint32_t) devid);
	if (common & ATTR_CMN_FSID)
	{
		uint32_t fsid[2] = { (uint32_t) devid, 0 };
		getattr_put(&p, fsid, sizeof(fsid));
	}
	if (common & ATTR_CMN_OBJTYPE)
		getattr_put_u32(&p, getattr_objtype(st.st_mode));
	if (common & ATTR_CMN_OBJTAG)
		getattr_put_u32(&p, VT_HFS); // pretend we're always on HFS
	if (common & ATTR_CMN_OBJID)
	{
		uint32_t id[2] = { (uint32_t) fileid, 0 };
		getattr_put(&p, id, sizeof(id));
	}
	if (common & ATTR_CMN_OBJPERMANENTID)
	{
		uint32_t id[2] = { (uint32_t) fileid, 0 };
		getattr_put(&p, id, sizeof(id));
	}
	if (common & ATTR_CMN_PAROBJID)
	{
		uint32_t id[2] = { (uint32_t) parentid, 0 };
		getattr_put(&p, id, sizeof(id));
	}
	if (common & ATTR_CMN_SCRIPT)
		getattr_put_u32(&p, 0); // kTextEncodingMacRoman
	if (common & ATTR_CMN_CRTIME)
		getattr_put_ts(&p, st.st_birthtimespec.tv_sec, st.st_birthtimespec.tv_nsec);
	if (common & ATTR_CMN_MODTIME)
		getattr_put_ts(&p, st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec);
	if (common & ATTR_CMN_CHGTIME)
		getattr_put_ts(&p, st.st_ctimespec.tv_sec, st.st_ctimespec.tv_nsec);
	if (common & ATTR_CMN_ACCTIME)
		getattr_put_ts(&p, st.st_atimespec.tv_sec, st.st_atimespec.tv_nsec);
	if (common & ATTR_CMN_BKUPTIME)
		getattr_put_ts(&p, 0, 0);
	if (common & ATTR_CMN_FNDRINFO)
	{
		char finfo[32];
		memset(finfo, 0, sizeof(finfo));
		if (objfd >= 0)
		{
			char procpath[32];
			__simple_sprintf(procpath, "/proc/self/fd/%d", objfd);
			LINUX_SYSCALL(__NR_getxattr, procpath, XATTR_FINDER_INFO, finfo, sizeof(finfo));
		}
		getattr_put(&p, finfo, sizeof(finfo));
	}
	if (common & ATTR_CMN_OWNERID)
		getattr_put_u32(&p, st.st_uid);
	if (common & ATTR_CMN_GRPID)
		getattr_put_u32(&p, st.st_gid);
	if (common & ATTR_CMN_ACCESSMASK)
		getattr_put_u32(&p, st.st_mode);
	if (common & ATTR_CMN_FLAGS)
		getattr_put_u32(&p, st.st_flags);
	if (common & ATTR_CMN_GEN_COUNT)
	{
		// x86Code: 0 means "not supported"; APFS counts content changes. Ours changes with the modification time
		// (never 0) for files and directories, which is what readers compare (FileProvider's libfssync).
		uint32_t gen = 0;
		if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))
		{
			gen = (uint32_t) (st.st_mtimespec.tv_sec * 1000003u) ^ (uint32_t) st.st_mtimespec.tv_nsec;
			if (!gen)
				gen = 1;
		}
		getattr_put_u32(&p, gen);
	}
	if (common & ATTR_CMN_DOCUMENT_ID)
	{
		// x86Code: APFS gives a document id to an item once it is UF_TRACKED (chflags, helper/misc/bsdflags.h), and
		// FileProvider's libfssync waits for it (EAGAIN while it is 0). Ours: the inode number's low 32 bits.
		uint32_t docid = 0;
		if (st.st_flags & 0x40 /* UF_TRACKED */)
			docid = (uint32_t) st.st_ino ? (uint32_t) st.st_ino : 1;
		// x86Code: and resolvable by fsgetpath/openbyid_np, as APFS resolves document ids
		if (docid && docid != fileid && fullpath[0])
			fsgetpath_remember((uint32_t) devid, docid, fullpath);
		getattr_put_u32(&p, docid);
	}
	if (common & ATTR_CMN_USERACCESS)
	{
		uint32_t access = 0;
		if (objfd >= 0)
		{
			char procpath[32];
			__simple_sprintf(procpath, "/proc/self/fd/%d", objfd);
			if (LINUX_SYSCALL(__NR_faccessat, LINUX_AT_FDCWD, procpath, 4 /* R_OK */, 0) == 0) access |= 4;
			if (LINUX_SYSCALL(__NR_faccessat, LINUX_AT_FDCWD, procpath, 2 /* W_OK */, 0) == 0) access |= 2;
			if (LINUX_SYSCALL(__NR_faccessat, LINUX_AT_FDCWD, procpath, 1 /* X_OK */, 0) == 0) access |= 1;
		}
		getattr_put_u32(&p, access);
	}
	if (common & ATTR_CMN_EXTENDED_SECURITY)
		getattr_put_ref(&p, "");
	if (common & ATTR_CMN_UUID)
	{
		char uuid[16];
		memset(uuid, 0, sizeof(uuid));
		getattr_put(&p, uuid, sizeof(uuid));
	}
	if (common & ATTR_CMN_GRPUUID)
	{
		char uuid[16];
		memset(uuid, 0, sizeof(uuid));
		getattr_put(&p, uuid, sizeof(uuid));
	}
	if (common & ATTR_CMN_FILEID)
		getattr_put_u64(&p, fileid);
	if (common & ATTR_CMN_PARENTID)
		getattr_put_u64(&p, parentid);
	if (common & ATTR_CMN_FULLPATH)
		getattr_put_ref(&p, fullpath);
	if (common & ATTR_CMN_ADDEDTIME)
		getattr_put_ts(&p, st.st_birthtimespec.tv_sec, st.st_birthtimespec.tv_nsec);
	if (common & ATTR_CMN_ERROR)
		getattr_put_u32(&p, 0);
	if (common & ATTR_CMN_DATA_PROTECT_FLAGS)
		getattr_put_u32(&p, 0);

	if (vol & ATTR_VOL_FSTYPE)
		getattr_put_u32(&p, 0);
	if (vol & ATTR_VOL_SIGNATURE)
		getattr_put_u32(&p, 0x482B); // 'H+'
	if (vol & ATTR_VOL_SIZE)
		getattr_put_u64(&p, (uint64_t) sfs.f_blocks * sfs.f_bsize);
	if (vol & ATTR_VOL_SPACEFREE)
		getattr_put_u64(&p, (uint64_t) sfs.f_bfree * sfs.f_bsize);
	if (vol & ATTR_VOL_SPACEAVAIL)
		getattr_put_u64(&p, (uint64_t) sfs.f_bavail * sfs.f_bsize);
	if (vol & ATTR_VOL_MINALLOCATION)
		getattr_put_u64(&p, sfs.f_bsize);
	if (vol & ATTR_VOL_ALLOCATIONCLUMP)
		getattr_put_u64(&p, sfs.f_bsize);
	if (vol & ATTR_VOL_IOBLOCKSIZE)
		getattr_put_u32(&p, sfs.f_iosize ? sfs.f_iosize : sfs.f_bsize);
	if (vol & ATTR_VOL_OBJCOUNT)
		getattr_put_u32(&p, (uint32_t) (sfs.f_files - sfs.f_ffree));
	if (vol & ATTR_VOL_FILECOUNT)
		getattr_put_u32(&p, (uint32_t) (sfs.f_files - sfs.f_ffree));
	if (vol & ATTR_VOL_DIRCOUNT)
		getattr_put_u32(&p, 0);
	if (vol & ATTR_VOL_MAXOBJCOUNT)
		getattr_put_u32(&p, (uint32_t) sfs.f_files);
	if (vol & ATTR_VOL_MOUNTPOINT)
		getattr_put_ref(&p, sfs.f_mntonname[0] ? sfs.f_mntonname : "/");
	if (vol & ATTR_VOL_NAME)
	{
		const char* vname = strrchr(sfs.f_mntonname, '/');
		getattr_put_ref(&p, (vname && vname[1]) ? vname + 1 : "Macintosh HD");
	}
	if (vol & ATTR_VOL_MOUNTFLAGS)
		getattr_put_u32(&p, sfs.f_flags);
	if (vol & ATTR_VOL_MOUNTEXTFLAGS) // x86Code: packed as XNU does, right after the mount flags
		getattr_put_u32(&p, 0);
	if (vol & ATTR_VOL_MOUNTEDDEVICE)
		getattr_put_ref(&p, sfs.f_mntfromname);
	if (vol & ATTR_VOL_ENCODINGSUSED)
		getattr_put_u64(&p, 0);
	if (vol & ATTR_VOL_CAPABILITIES)
	{
		// What a Linux file system (and Darling's syscall layer) provides
		// x86Code: inode numbers are persistent object IDs (ext4/btrfs/xfs), and fsgetpath resolves the IDs
		// getattrlist handed out (impl/misc/fsgetpath.c). Without PATH_FROM_ID CoreServicesInternal has no
		// file ID (_kCFURLFileIDKey NULL), so LaunchServices cannot make an FSNode for an executable: no
		// executable info, every record platform 0, extensions not found by bundle ID (-10814)
		uint32_t caps[8] = { 0 };
		caps[VOL_CAPABILITIES_FORMAT] = VOL_CAP_FMT_PERSISTENTOBJECTIDS | VOL_CAP_FMT_PATH_FROM_ID | VOL_CAP_FMT_SYMBOLICLINKS | VOL_CAP_FMT_HARDLINKS
			| VOL_CAP_FMT_SPARSE_FILES | VOL_CAP_FMT_CASE_SENSITIVE | VOL_CAP_FMT_CASE_PRESERVING
			| VOL_CAP_FMT_FAST_STATFS | VOL_CAP_FMT_2TB_FILESIZE | VOL_CAP_FMT_64BIT_OBJECT_IDS;
		caps[VOL_CAPABILITIES_INTERFACES] = VOL_CAP_INT_ATTRLIST | VOL_CAP_INT_ADVLOCK | VOL_CAP_INT_FLOCK
			| VOL_CAP_INT_USERACCESS | VOL_CAP_INT_EXTENDED_ATTR | VOL_CAP_INT_RENAME_SWAP | VOL_CAP_INT_RENAME_EXCL;
		// valid[]: every capability bit is answered
		caps[4] = caps[5] = 0xFFFFFFFF;
		getattr_put(&p, caps, sizeof(caps));
	}
	if (vol & ATTR_VOL_UUID)
	{
		uint64_t uuid[2] = { sfs.f_fsid, 0 };
		getattr_put(&p, uuid, sizeof(uuid));
	}
	if (vol & ATTR_VOL_SPACEUSED) // x86Code
		getattr_put_u64(&p, (uint64_t) (sfs.f_blocks - sfs.f_bfree) * sfs.f_bsize);
	if (vol & ATTR_VOL_QUOTA_SIZE)
		getattr_put_u64(&p, 0);
	if (vol & ATTR_VOL_RESERVED_SIZE)
		getattr_put_u64(&p, 0);
	if (vol & ATTR_VOL_ATTRIBUTES)
	{
		// vol_attributes_attr_t: valid and native attribute_set_t
		uint32_t attrs[10] = {
			ATTR_CMN_VALIDMASK & ~(ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID | ATTR_CMN_ERROR),
			ATTR_VOL_VALIDMASK, ATTR_DIR_VALIDMASK, ATTR_FILE_VALIDMASK & ~ATTR_FILE_DATAEXTENTS, 0,
		};
		memcpy(&attrs[5], attrs, 5 * sizeof(uint32_t));
		getattr_put(&p, attrs, sizeof(attrs));
	}
	// x86Code: the type name is the one statfs reports (apfs, see the statfs conversion); subtype 0, owner root
	if (vol & ATTR_VOL_FSTYPENAME)
		getattr_put_ref(&p, sfs.f_fstypename);
	if (vol & ATTR_VOL_FSSUBTYPE)
		getattr_put_u32(&p, 0);
	if (vol & ATTR_VOL_OWNER)
		getattr_put_u32(&p, 0);

	if (dir & ATTR_DIR_LINKCOUNT)
		getattr_put_u32(&p, st.st_nlink);
	if (dir & ATTR_DIR_ENTRYCOUNT)
	{
		uint32_t count = 0;
		if (objfd >= 0)
		{
			int dfd = LINUX_SYSCALL(__NR_openat, objfd, ".", LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_CLOEXEC, 0);
			if (dfd >= 0)
			{
				count = getattr_count_entries(dfd);
				close_internal(dfd);
			}
		}
		getattr_put_u32(&p, count);
	}
	if (dir & ATTR_DIR_MOUNTSTATUS)
		getattr_put_u32(&p, mntstatus);
	if (dir & ATTR_DIR_ALLOCSIZE)
		getattr_put_u64(&p, st.st_blocks * 512);
	if (dir & ATTR_DIR_IOBLOCKSIZE)
		getattr_put_u32(&p, st.st_blksize);
	if (dir & ATTR_DIR_DATALENGTH)
		getattr_put_u64(&p, st.st_size);

	if (file & ATTR_FILE_LINKCOUNT)
		getattr_put_u32(&p, st.st_nlink);
	if (file & ATTR_FILE_TOTALSIZE)
		getattr_put_u64(&p, st.st_size);
	if (file & ATTR_FILE_ALLOCSIZE)
		getattr_put_u64(&p, st.st_blocks * 512);
	if (file & ATTR_FILE_IOBLOCKSIZE)
		getattr_put_u32(&p, st.st_blksize);
	if (file & ATTR_FILE_CLUMPSIZE)
		getattr_put_u32(&p, st.st_blksize);
	if (file & ATTR_FILE_DEVTYPE)
		getattr_put_u32(&p, (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) ? st.st_rdev : 0);
	if (file & ATTR_FILE_FILETYPE)
		getattr_put_u32(&p, 0);
	if (file & ATTR_FILE_FORKCOUNT)
		getattr_put_u32(&p, 1);
	if (file & ATTR_FILE_FORKLIST)
		getattr_put_ref(&p, "");
	if (file & ATTR_FILE_DATALENGTH)
		getattr_put_u64(&p, st.st_size);
	if (file & ATTR_FILE_DATAALLOCSIZE)
		getattr_put_u64(&p, st.st_blocks * 512);
	if (file & ATTR_FILE_RSRCLENGTH)
	{
		uint64_t len = 0;
		if (objfd >= 0)
		{
			char procpath[32];
			__simple_sprintf(procpath, "/proc/self/fd/%d", objfd);
			rv = LINUX_SYSCALL(__NR_getxattr, procpath, XATTR_RESOURCE_FORK, NULL, 0);
			if (rv > 0)
				len = rv;
		}
		getattr_put_u64(&p, len);
	}
	if (file & ATTR_FILE_RSRCALLOCSIZE)
		getattr_put_u64(&p, 0);

	if (cmnext & ATTR_CMNEXT_RELPATH)
		getattr_put_ref(&p, "");
	if (cmnext & ATTR_CMNEXT_PRIVATESIZE)
		getattr_put_u64(&p, 0);
	if (cmnext & ATTR_CMNEXT_LINKID)
		getattr_put_u64(&p, fileid);
	if (cmnext & ATTR_CMNEXT_NOFIRMLINKPATH)
		getattr_put_ref(&p, fullpath);
	if (cmnext & ATTR_CMNEXT_REALDEVID)
		getattr_put_u32(&p, (uint32_t) devid);
	if (cmnext & ATTR_CMNEXT_REALFSID)
	{
		uint32_t fsid[2] = { (uint32_t) devid, 0 };
		getattr_put(&p, fsid, sizeof(fsid));
	}
	if (cmnext & ATTR_CMNEXT_CLONEID)
		getattr_put_u64(&p, fileid); // x86Code: an uncloned APFS file's clone ID is its own ID
	if (cmnext & ATTR_CMNEXT_EXT_FLAGS)
		getattr_put_u64(&p, 0);
	if (cmnext & ATTR_CMNEXT_RECURSIVE_GENCOUNT)
		getattr_put_u64(&p, 0);
	if (cmnext & ATTR_CMNEXT_ATTRIBUTION_TAG)
		getattr_put_u64(&p, 0);
	if (cmnext & ATTR_CMNEXT_CLONE_REFCNT)
		getattr_put_u32(&p, 0);

	if (objfd >= 0)
		close_internal(objfd);

	__SIZE_TYPE__ spaceNeeded = p.var - ourBuffer;
	if (spaceNeeded > bufsize)
		spaceNeeded = bufsize;

	// The length word holds what was returned, or the full size with FSOPT_REPORT_FULLSIZE
	*((uint32_t*) ourBuffer) = (options & FSOPT_REPORT_FULLSIZE) ? spaceNeeded : min(bufferSize, spaceNeeded);

	memcpy(attributeBuffer, ourBuffer, min(bufferSize, spaceNeeded));

	return 0;
}
