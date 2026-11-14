#include <sys/stat.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h>

#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/ftruncate.h>
#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/lstat.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>

// x86Sim: XNU resolves (fsid, object ID) to a path in the file system. Linux cannot look up an
// inode by number, so we answer for the IDs this process has seen through getattrlist
// (ATTR_CMN_FILEID/OBJID, CMNEXT_LINKID), which is what CoreServicesInternal resolves (file
// reference URLs, FSNode). Unknown IDs fail with ENOENT as for a deleted file.
#define FSGP_SLOTS 256
#define FSGP_PATH 1024

static struct fsgp_entry
{
	unsigned int dev;
	unsigned long long ino;
	char path[FSGP_PATH];
} fsgp_cache[FSGP_SLOTS];
static int fsgp_lock;

static void fsgp_acquire(void)
{
	while (__atomic_exchange_n(&fsgp_lock, 1, __ATOMIC_ACQUIRE))
		__builtin_ia32_pause();
}

static void fsgp_release(void)
{
	__atomic_store_n(&fsgp_lock, 0, __ATOMIC_RELEASE);
}

static unsigned int fsgp_slot(unsigned int dev, unsigned long long ino)
{
	unsigned long long h = (ino ^ ((unsigned long long) dev << 40)) * 0x9E3779B97F4A7C15ull;
	return (unsigned int) (h >> 56) % FSGP_SLOTS;
}

// x86Sim: a table shared by every process of the prefix, so an ID one process handed out resolves in another.
// A bookmark that Safari makes for WebKit's cache directory is resolved in the GPU process; with only the
// per-process cache that failed, CoreServicesInternal took the directory for an iCloud document that isn't
// downloaded (its parent is reachable) and waited in DownloadCloudDocumentSync for ever (Safari then killed
// the GPU process, over and over). /private/var/db/x86sim-fileids, 16384 slots of 512 bytes, last writer wins;
// a hit is used only if the path still has that ID.
#define FSGP_SH_SLOTS 16384
#define FSGP_SH_PATH 496
struct fsgp_shared
{
	unsigned int dev;
	unsigned int len;
	unsigned long long ino;
	char path[FSGP_SH_PATH];
};
static struct fsgp_shared* fsgp_sh;
static int fsgp_sh_state; // 0 not tried, 1 mapped, -1 unavailable

static struct fsgp_shared* fsgp_shared_table(void)
{
	int st = __atomic_load_n(&fsgp_sh_state, __ATOMIC_ACQUIRE);
	if (st)
		return st > 0 ? fsgp_sh : NULL;
	int fd = sys_open("/private/var/db/x86sim-fileids", 0x0002 /* O_RDWR */ | 0x0200 /* O_CREAT */ | 0x01000000 /* O_CLOEXEC */, 0666);
	void* m = (void*) -1;
	if (fd >= 0)
	{
		unsigned long size = FSGP_SH_SLOTS * sizeof(struct fsgp_shared);
		if (sys_ftruncate(fd, size) == 0)
			m = sys_mmap(NULL, size, 3 /* PROT_READ|PROT_WRITE */, 1 /* MAP_SHARED */, fd, 0);
		sys_close(fd);
	}
	if (m == (void*) -1 || (unsigned long) m > (unsigned long) -4096)
	{
		__atomic_store_n(&fsgp_sh_state, -1, __ATOMIC_RELEASE);
		return NULL;
	}
	fsgp_sh = m;
	__atomic_store_n(&fsgp_sh_state, 1, __ATOMIC_RELEASE);
	return fsgp_sh;
}

static unsigned int fsgp_sh_slot(unsigned int dev, unsigned long long ino)
{
	unsigned long long h = (ino ^ ((unsigned long long) dev << 40)) * 0x9E3779B97F4A7C15ull;
	return (unsigned int) (h >> 40) % FSGP_SH_SLOTS;
}

static struct fsgp_shared* fsgetpath_shared_table_public(void) { return fsgp_shared_table(); }
// the shared slot of (dev, ino) when it holds that object
static struct fsgp_shared* fsgetpath_shared_known(unsigned int dev, unsigned long long ino)
{
	struct fsgp_shared* t = ino ? fsgp_shared_table() : NULL;
	if (!t)
		return NULL;
	struct fsgp_shared* e = &t[fsgp_sh_slot(dev, ino)];
	return (__atomic_load_n(&e->ino, __ATOMIC_ACQUIRE) == ino && e->dev == dev) ? e : NULL;
}

void fsgetpath_remember(unsigned int dev, unsigned long long ino, const char* path)
{
	{
		__SIZE_TYPE__ len = __simple_strlen(path);
		struct fsgp_shared* t = (ino && len && len < FSGP_SH_PATH) ? fsgp_shared_table() : NULL;
		if (t)
		{
			struct fsgp_shared* e = &t[fsgp_sh_slot(dev, ino)];
			if (!(e->ino == ino && e->dev == dev && e->len == len))
			{
				e->ino = 0;
				for (__SIZE_TYPE__ i = 0; i <= len; i++)
					e->path[i] = path[i];
				e->dev = dev;
				e->len = (unsigned int) len;
				__atomic_store_n(&e->ino, ino, __ATOMIC_RELEASE);
			}
		}
	}

	__SIZE_TYPE__ len = __simple_strlen(path);
	if (!ino || !len || len >= FSGP_PATH)
		return;
	struct fsgp_entry* e = &fsgp_cache[fsgp_slot(dev, ino)];
	fsgp_acquire();
	e->dev = dev;
	e->ino = ino;
	for (__SIZE_TYPE__ i = 0; i <= len; i++)
		e->path[i] = path[i];
	fsgp_release();
}

static long fsgetpath_volume_root(const char* buf, unsigned long size, unsigned int dev);

// x86Sim: XNU's fsgetpath follows an object wherever it is renamed to; ours answers from the paths remembered when
// IDs went out, re-checked with lstat. So a renamed file's ID resolved to nothing (ENOENT): a bookmark to a file
// that was renamed (CFURL then resolves it by file ID) failed "The file doesn't exist", where Apple's resolves to
// the new name. sys_renameat / renameatx_np now move the remembered path of the object (and of every entry under a
// renamed directory) to the new location.
#define FSGP_LINUX_O_PATH 010000000
#define FSGP_LINUX_O_NOFOLLOW 0400000
#define FSGP_LINUX_O_CLOEXEC 02000000
#define FSGP_LINUX_AT_SYMLINK_NOFOLLOW 0x100

static int fsgp_guest_path(int ldfd, const char* lpath, char* out, unsigned long size)
{
	int fd = LINUX_SYSCALL(__NR_openat, ldfd, lpath, FSGP_LINUX_O_PATH | FSGP_LINUX_O_NOFOLLOW | FSGP_LINUX_O_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	int rv = fdpath(fd, out, size);
	LINUX_SYSCALL(__NR_close, fd);
	return rv < 0 ? -1 : 0;
}

void fsgetpath_rename_prepare(int ldfd, const char* lpath, struct fsgp_rename* r)
{
	struct linux_stat lst;
	r->known = r->isdir = 0;
	r->oldpath[0] = 0;
	if (LINUX_SYSCALL(__NR_newfstatat, ldfd, lpath, &lst, FSGP_LINUX_AT_SYMLINK_NOFOLLOW) < 0)
		return;
	r->dev = (unsigned int) lst.st_dev;
	r->ino = lst.st_ino;
	r->isdir = (lst.st_mode & 0170000) == 0040000;
	struct fsgp_shared* t = fsgetpath_shared_known(r->dev, r->ino);
	if (t)
	{
		unsigned int len = t->len;
		if (len < sizeof(r->oldpath) && len < FSGP_SH_PATH)
		{
			for (unsigned int i = 0; i < len; i++)
				r->oldpath[i] = t->path[i];
			r->oldpath[len] = 0;
			r->known = 1;
		}
	}
	else
	{
		struct fsgp_entry* e = &fsgp_cache[fsgp_slot(r->dev, r->ino)];
		fsgp_acquire();
		if (e->ino == r->ino && e->dev == r->dev)
		{
			__SIZE_TYPE__ len = __simple_strlen(e->path);
			for (__SIZE_TYPE__ i = 0; i <= len; i++)
				r->oldpath[i] = e->path[i];
			r->known = 1;
		}
		fsgp_release();
	}
	// a directory's own ID need not have gone out for IDs under it to have: its old path for the prefix rewrite
	if (!r->known && r->isdir && fsgp_guest_path(ldfd, lpath, r->oldpath, sizeof(r->oldpath)) < 0)
		r->oldpath[0] = 0;
}

static int fsgp_rebase(char* dst, unsigned long size, const char* path, __SIZE_TYPE__ oldlen, const char* newpath)
{
	// path = <old>/<rest> -> <new>/<rest>
	__SIZE_TYPE__ nlen = __simple_strlen(newpath), rlen = __simple_strlen(path + oldlen);
	if (nlen + rlen + 1 > size)
		return -1;
	for (__SIZE_TYPE__ i = 0; i < nlen; i++)
		dst[i] = newpath[i];
	for (__SIZE_TYPE__ i = 0; i <= rlen; i++)
		dst[nlen + i] = path[oldlen + i];
	return 0;
}

void fsgetpath_rename_done(int ldfd, const char* lpath, const struct fsgp_rename* r)
{
	if (!r->known && !(r->isdir && r->oldpath[0]))
		return;
	char newpath[FSGP_PATH];
	if (fsgp_guest_path(ldfd, lpath, newpath, sizeof(newpath)) < 0)
		return;
	if (r->known)
		fsgetpath_remember(r->dev, r->ino, newpath);
	if (!r->isdir || !r->oldpath[0])
		return;
	__SIZE_TYPE__ oldlen = __simple_strlen(r->oldpath);
	if (oldlen < 2)
		return;
	struct fsgp_shared* t = fsgetpath_shared_table_public();
	for (unsigned int i = 0; t && i < FSGP_SH_SLOTS; i++)
	{
		struct fsgp_shared* e = &t[i];
		unsigned long long ino = __atomic_load_n(&e->ino, __ATOMIC_ACQUIRE);
		unsigned int len = e->len;
		if (!ino || e->dev != r->dev || len <= oldlen || len >= FSGP_SH_PATH || e->path[oldlen] != '/')
			continue;
		int match = 1;
		for (__SIZE_TYPE__ k = 0; k < oldlen && match; k++)
			match = e->path[k] == r->oldpath[k];
		if (!match)
			continue;
		char old[FSGP_SH_PATH], moved[FSGP_SH_PATH];
		for (unsigned int k = 0; k < len; k++)
			old[k] = e->path[k];
		old[len] = 0;
		if (fsgp_rebase(moved, sizeof(moved), old, oldlen, newpath) == 0 && e->ino == ino)
			fsgetpath_remember(r->dev, ino, moved);
	}
	fsgp_acquire();
	for (unsigned int i = 0; i < FSGP_SLOTS; i++)
	{
		struct fsgp_entry* e = &fsgp_cache[i];
		if (!e->ino || e->dev != r->dev || e->path[oldlen] != '/' || __simple_strlen(e->path) <= oldlen)
			continue;
		int match = 1;
		for (__SIZE_TYPE__ k = 0; k < oldlen && match; k++)
			match = e->path[k] == r->oldpath[k];
		char moved[FSGP_PATH];
		if (match && fsgp_rebase(moved, sizeof(moved), e->path, oldlen, newpath) == 0)
			for (__SIZE_TYPE__ k = 0, n = __simple_strlen(moved); k <= n; k++)
				e->path[k] = moved[k];
	}
	fsgp_release();
}

long sys_fsgetpath(const char* buf, unsigned long size, void* fsid, unsigned long long objid)
{
	if (!buf || !fsid)
		return -EFAULT;
	unsigned int dev = ((unsigned int*) fsid)[0];
	struct fsgp_entry* e = &fsgp_cache[fsgp_slot(dev, objid)];
	long rv = -ENOENT;
	fsgp_acquire();
	if (e->ino == objid && e->dev == dev)
	{
		__SIZE_TYPE__ len = __simple_strlen(e->path);
		if (len + 1 > size)
			rv = -ENOSPC;
		else
		{
			for (__SIZE_TYPE__ i = 0; i <= len; i++)
				((char*) buf)[i] = e->path[i];
			rv = len + 1;
		}
	}
	fsgp_release();
	if (rv == -ENOENT)
	{
		struct fsgp_shared* t = fsgp_shared_table();
		if (t)
		{
			struct fsgp_shared* e = &t[fsgp_sh_slot(dev, objid)];
			char tmp[FSGP_SH_PATH];
			unsigned int len = e->len;
			if (__atomic_load_n(&e->ino, __ATOMIC_ACQUIRE) == objid && e->dev == dev && len < FSGP_SH_PATH)
			{
				for (unsigned int i = 0; i < len; i++)
					tmp[i] = e->path[i];
				tmp[len] = 0;
				struct stat64 st;
				// still the same object (a writer may have changed the slot meanwhile, inodes get reused); a document id
				// (getattrlist ATTR_CMN_DOCUMENT_ID) is the inode's low 32 bits
				if (e->ino == objid && sys_lstat64(tmp, &st) == 0 && (st.st_ino == objid || (objid <= 0xffffffffull && (uint32_t) st.st_ino == objid)) && (unsigned int) st.st_dev == dev)
				{
					if (len + 1 > size)
						rv = -ENOSPC;
					else
					{
						for (unsigned int i = 0; i <= len; i++)
							((char*) buf)[i] = tmp[i];
						rv = len + 1;
					}
				}
			}
		}
	}
	if (rv == -ENOENT && objid == 2)
		rv = fsgetpath_volume_root(buf, size, dev);
	return rv;
}

// x86Sim: object id 2 is the root directory of an APFS/HFS volume (revisiond opens a volume by (fsid, 2) for its
// document-id library; "Failed creating library for 58"). Linux roots have other inode numbers: the mount point
// is found from any path of that device the table knows, walking up while the parent is on the same device.
static long fsgetpath_volume_root(const char* buf, unsigned long size, unsigned int dev)
{
	struct fsgp_shared* t = fsgp_shared_table();
	if (!t)
		return -ENOENT;
	char path[FSGP_SH_PATH];
	int found = 0;
	for (unsigned int i = 0; i < FSGP_SH_SLOTS && !found; i++)
	{
		struct fsgp_shared* e = &t[i];
		unsigned int len = e->len;
		if (!__atomic_load_n(&e->ino, __ATOMIC_ACQUIRE) || e->dev != dev || len == 0 || len >= FSGP_SH_PATH || e->path[0] != '/')
			continue;
		for (unsigned int k = 0; k < len; k++)
			path[k] = e->path[k];
		path[len] = 0;
		struct stat64 st;
		found = sys_lstat64(path, &st) == 0 && (unsigned int) st.st_dev == dev;
	}
	if (!found)
		return -ENOENT;
	for (;;)
	{
		__SIZE_TYPE__ len = __simple_strlen(path);
		while (len > 1 && path[len - 1] != '/')
			len--;
		if (len <= 1)
		{
			struct stat64 st;
			if (sys_lstat64("/", &st) == 0 && (unsigned int) st.st_dev == dev)
				path[0] = '/', path[1] = 0;
			break;
		}
		char parent[FSGP_SH_PATH];
		for (__SIZE_TYPE__ k = 0; k < len - 1; k++)
			parent[k] = path[k];
		parent[len - 1] = 0;
		struct stat64 st;
		if (sys_lstat64(parent, &st) != 0 || (unsigned int) st.st_dev != dev)
			break;
		for (__SIZE_TYPE__ k = 0; k < len; k++)
			path[k] = parent[k];
	}
	__SIZE_TYPE__ len = __simple_strlen(path);
	if (len + 1 > size)
		return -ENOSPC;
	for (__SIZE_TYPE__ k = 0; k <= len; k++)
		((char*) buf)[k] = path[k];
	return len + 1;
}

// x86Sim: openbyid_np (BSD 479) was missing (ENOSYS). APFS opens a file by its object id or by its document id;
// GenerationalStorage resolves a document id that way (GSLibraryResolveDocumentId2: openbyid_np, then checks the
// document id of what it opened), and FileProviderResolver with it every "did=" item identifier: Preview could
// not open a file handed over by Files ("Error resolving bookmark ... did=... -1005"). Resolved like fsgetpath,
// then opened by path.
long sys_openbyid_np(void* fsid, void* objid, int oflags)
{
	char path[FSGP_PATH];
	if (!fsid || !objid)
		return -EFAULT;
	long rv = sys_fsgetpath(path, sizeof(path), fsid, *(unsigned long long*) objid);
	if (rv < 0)
		return rv;
	return sys_open(path, oflags, 0);
}
