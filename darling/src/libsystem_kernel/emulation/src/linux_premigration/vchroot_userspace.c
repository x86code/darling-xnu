
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#ifdef TEST
#	include <unistd.h>
#	include <sys/stat.h>
#	include <sys/syscall.h>
#	include <stdio.h>
#	include <stdbool.h>
#	include <stdlib.h>
#	include <string.h>
#	include <errno.h>
#	include <dirent.h>
#	include <fcntl.h>

#	define LINUX_SYSCALL(...) ({ int __rv = syscall(__VA_ARGS__); if (__rv == -1) __rv = -errno; __rv; })
#	define LINUX_ENOENT ENOENT
#	define LINUX_ELOOP ELOOP
#	define LINUX_ENAMETOOLONG ENAMETOOLONG

#	define LINUX_S_IFMT S_IFMT
#	define LINUX_S_IFLNK S_IFLNK

#	define LINUX_O_RDONLY O_RDONLY

#	define __simple_sprintf sprintf
#	define linux_dirent64 dirent
typedef struct stat stat_t;
#else
#	include <stdbool.h>
#   include <stddef.h>

#	include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#	include <darling/emulation/common/base.h>
#	include <darling/emulation/other/mach/lkm.h>
#	include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#	include <darling/emulation/common/simple.h>
#	include <darling/emulation/conversion/dirent/getdirentries.h>
#	include <darling/emulation/conversion/errno.h>
#	include <darling/emulation/conversion/fcntl/open.h>
#	include <darling/emulation/conversion/duct_errno.h>
#	include <darling/emulation/conversion/stat/common.h>
#	include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>
#	include <darling/emulation/conversion/common_at.h>

#include <darlingserver/rpc.h>

typedef struct linux_stat stat_t;

struct _xlocale;
typedef struct _xlocale* locale_t;

#define LC_C_LOCALE ((locale_t)NULL)

extern __SIZE_TYPE__ strlen(const char* s);
extern char* strcpy(char* dest, const char* src);
extern int strcmp(const char* str1, const char* str2);
extern int strncmp(const char* str1, const char* str2, __SIZE_TYPE__ n);
extern int strncasecmp_l(const char* str1, const char* str2, __SIZE_TYPE__ n, locale_t locale);
extern int strcasecmp(const char* str1, const char* str2);
extern char* strcat(char* dest, const char* src);
extern char *strchr(const char *s, int c);
extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern void* memmove(void* dest, const void* src, __SIZE_TYPE__ n);
extern int memcmp(const void* dest, const void* src, __SIZE_TYPE__ n);

#define LINUX_S_IFMT 00170000
#define LINUX_S_IFLNK 0120000

#endif

static bool next_component(const char* from, const char** end);

static char prefix_path[4096] = {0}; // MUST NOT end with '/'
static int prefix_path_len = -1;

static const char EXIT_PATH[] = "/Volumes/SystemRoot";

#ifndef TEST
#ifdef VARIANT_DYLD
#define icase_enabled false
#else
#define icase_enabled true
#endif

#else
static bool icase_enabled = true;
#endif

static const int MAX_SYMLINK_DEPTH = 10;

struct context
{
	const char* current_root;
	int current_root_len;

	char current_path[4096];
	int current_path_len;

	int symlink_depth;
	bool unknown_component;
	bool follow;
};

static int vchroot_run(const char* path, struct context* ctxt);

#ifndef TEST
VISIBLE
#endif
int __darling_vchroot(int dfd)
{
	int rv;

#ifndef TEST
	rv = errno_linux_to_bsd(dserver_rpc_vchroot(dfd));
	if (rv != 0)
		return rv;
#endif

	char buf[50];

	__simple_sprintf(buf, "/proc/self/fd/%d", dfd);

	#if defined(__NR_readlink)
		rv = LINUX_SYSCALL(__NR_readlink, buf, prefix_path, sizeof(prefix_path) - 1);
	#else
		rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, buf, prefix_path, sizeof(prefix_path) - 1);
	#endif
	prefix_path[rv] = '\0';
	prefix_path_len = rv;

	return 0;
}

#ifndef TEST
VISIBLE
int __darling_vchroot_expand(const char* path, char* out)
{
	struct vchroot_expand_args a = {
		.dfd = -100,
		.flags = 0
	};

	strcpy(a.path, path);

	int rv = vchroot_expand(&a);

	strcpy(out, a.path);
	return rv;
}
#endif

static void init_vchroot_path(void)
{
	uint64_t tmp_len;
	int code = dserver_rpc_vchroot_path(prefix_path, sizeof(prefix_path), &tmp_len);
	if (code < 0) {
		__simple_kprintf("Failed to get vchroot path: %d\n", code);
		__simple_abort();
	}

	prefix_path_len = (int)tmp_len;
}

#ifndef TEST
// x86Sim: fast path. The walk below lstat()s every component of every path (installd's post-boot scan: ~21,000
// lstat/s; every dyld load, every open/stat of an app). openat2() resolves the whole path in the kernel with the same
// meaning: RESOLVE_IN_ROOT on a descriptor of the prefix makes absolute symlinks resolve inside the prefix, as the walk
// does. Paths into the real root (/Volumes/SystemRoot/...) are resolved with RESOLVE_NO_SYMLINKS (the walk resolves an
// absolute symlink there inside the prefix, the kernel would not). Everything unusual goes the old way: "..", /proc,
// a nested /Volumes/SystemRoot, a result inside the prefix's /proc or /Volumes/SystemRoot mounts, any error. A missing
// last component (create, probes of absent files) resolves its directory this way and runs the walk for the last
// component only (its case-insensitive lookup, a dangling symlink). Nothing is cached, so nothing goes stale.
#define VCH_O_PATH 010000000
#define VCH_O_DIRECTORY 0200000
#define VCH_O_NOFOLLOW 0400000
#define VCH_O_CLOEXEC 02000000
#define VCH_RESOLVE_NO_MAGICLINKS 0x02
#define VCH_RESOLVE_NO_SYMLINKS 0x04
#define VCH_RESOLVE_IN_ROOT 0x10
#define VCH_FALLBACK (-100000)
struct vch_open_how { unsigned long long flags, mode, resolve; };
static int vch_fast_off;
static int vch_prefix_fd = -1;
static unsigned long long vch_prefix_dev, vch_prefix_ino;

static int vch_prefix_fd_get(void)
{
	stat_t st;
	// the process may have closed our descriptor (closefrom) and reused its number: check it still is the prefix
	if (vch_prefix_fd >= 0 && LINUX_SYSCALL(__NR_fstat, vch_prefix_fd, &st) == 0 &&
		st.st_dev == vch_prefix_dev && st.st_ino == vch_prefix_ino)
		return vch_prefix_fd;
	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, prefix_path, VCH_O_PATH | VCH_O_DIRECTORY | VCH_O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (LINUX_SYSCALL(__NR_fstat, fd, &st) != 0)
	{
		LINUX_SYSCALL(__NR_close, fd);
		return -1;
	}
	vch_prefix_dev = st.st_dev;
	vch_prefix_ino = st.st_ino;
	vch_prefix_fd = fd;
	return fd;
}

// is `p` (at a component start, after a '/') "Volumes/SystemRoot" followed by '/' or the end
static bool vch_is_exit_component(const char* p)
{
	return strncasecmp_l(p, EXIT_PATH + 1, sizeof(EXIT_PATH) - 2, LC_C_LOCALE) == 0 &&
		(p[sizeof(EXIT_PATH) - 2] == '/' || p[sizeof(EXIT_PATH) - 2] == '\0');
}

// paths the fast path leaves to the walk: "..", a /Volumes/SystemRoot anywhere, a leading /proc (in the prefix)
static bool vch_plain(const char* path, bool in_prefix)
{
	if (in_prefix && strncmp(path, "/proc", 5) == 0 && (path[5] == '/' || path[5] == '\0'))
		return false;
	for (const char* p = path; *p; p++)
	{
		if (*p != '/')
			continue;
		if (p[1] == '.' && p[2] == '.' && (p[3] == '/' || p[3] == '\0'))
			return false;
		if (vch_is_exit_component(p + 1))
			return false;
	}
	return true;
}

// resolve `path` (absolute, in the prefix or in the real root): the Linux path in `out` and its length,
// -LINUX_ENOENT, or VCH_FALLBACK (or another negative error) for "use the walk"
static int vch_resolve(const char* path, bool in_prefix, bool follow, char* out, int outsize)
{
	struct vch_open_how how = {
		.flags = VCH_O_PATH | VCH_O_CLOEXEC | (follow ? 0 : VCH_O_NOFOLLOW),
		.mode = 0,
		.resolve = VCH_RESOLVE_NO_MAGICLINKS | (in_prefix ? VCH_RESOLVE_IN_ROOT : VCH_RESOLVE_NO_SYMLINKS),
	};
	int dfd = LINUX_AT_FDCWD;
	if (in_prefix)
	{
		dfd = vch_prefix_fd_get();
		if (dfd < 0)
			return VCH_FALLBACK;
	}
	int fd = LINUX_SYSCALL(__NR_openat2, dfd, path, &how, sizeof(how));
	if (fd < 0)
	{
		if (fd == -38 /* ENOSYS */ || fd == -22 /* EINVAL: unknown openat2 flags */)
			vch_fast_off = 1;
		return fd;
	}
	char buf[50];
	__simple_sprintf(buf, "/proc/self/fd/%d", fd);
	int rv = LINUX_SYSCALL(__NR_readlink, buf, out, outsize - 1);
	LINUX_SYSCALL(__NR_close, fd);
	if (rv <= 0 || rv >= outsize - 1)
		return VCH_FALLBACK;
	out[rv] = '\0';
	if (in_prefix)
	{
		// must be the prefix or below it, and not inside its /proc or /Volumes/SystemRoot mounts
		if (rv < prefix_path_len || strncmp(out, prefix_path, prefix_path_len) != 0 ||
			(out[prefix_path_len] != '/' && out[prefix_path_len] != '\0'))
			return VCH_FALLBACK;
		const char* rest = out + prefix_path_len;
		if ((strncmp(rest, "/proc", 5) == 0 && (rest[5] == '/' || rest[5] == '\0')) ||
			(rest[0] == '/' && vch_is_exit_component(rest + 1)))
			return VCH_FALLBACK;
	}
	return rv;
}

// x86Sim: "/proc/<pid>/<file>" for a few plain files of the prefix's procfs. The walk lstat()s /proc, /proc/<pid>
// and the file for each: launchd_sim reads /proc/<pid>/stat and cmdline of the requestor for every lookup it logs
// (~2,000 lstat a second while an app launches). None of them is a symlink (unlike /proc/self, exe, cwd, root, fd/),
// so the walk's result is the prefix followed by the path; a pid that doesn't exist fails in the caller's syscall.
static bool vch_proc_file(const char* path)
{
	static const char* const files[] = { "stat", "cmdline", "status", "statm", "comm", "environ", "auxv", NULL };
	if (strncmp(path, "/proc/", 6) != 0 || path[6] < '1' || path[6] > '9')
		return false;
	const char* p = path + 6;
	while (*p >= '0' && *p <= '9')
		p++;
	if (*p++ != '/')
		return false;
	for (int i = 0; files[i]; i++)
		if (strcmp(p, files[i]) == 0)
			return true;
	return false;
}

// true if it produced the result (ctxt->current_path, *out_rv); false: run the walk as before
static bool vchroot_fast(struct context* ctxt, const char* input_path, int* out_rv)
{
	char path[4096];
	bool in_prefix;
	int n;

	if (vch_fast_off)
		return false;

	if (*input_path == '/')
	{
		if (ctxt->current_root_len == 0)
			return false;
		if (vch_is_exit_component(input_path + 1))
		{
			const char* rest = input_path + sizeof(EXIT_PATH) - 1;
			if (*rest != '/')
				return false;
			in_prefix = false;
			n = strlen(rest);
			if (n + 1 > (int)sizeof(path))
				return false;
			memcpy(path, rest, n + 1);
		}
		else
		{
			in_prefix = true;
			n = strlen(input_path);
			if (n + 1 > (int)sizeof(path))
				return false;
			memcpy(path, input_path, n + 1);
			if (vch_proc_file(path) && prefix_path_len + n + 1 <= (int)sizeof(ctxt->current_path))
			{
				memcpy(ctxt->current_path, prefix_path, prefix_path_len);
				memcpy(ctxt->current_path + prefix_path_len, path, n + 1);
				ctxt->current_path_len = prefix_path_len + n;
				*out_rv = 0;
				return true;
			}
		}
	}
	else
	{
		// relative to a directory (ctxt->current_path, a Linux path): in the prefix or in the real root
		in_prefix = ctxt->current_root_len > 0;
		const char* dir = ctxt->current_path + ctxt->current_root_len;
		int dl = ctxt->current_path_len - ctxt->current_root_len;
		int il = strlen(input_path);
		if (dl + il + 2 > (int)sizeof(path))
			return false;
		memcpy(path, dir, dl);
		path[dl] = '/';
		memcpy(path + dl + 1, input_path, il + 1);
		n = dl + 1 + il;
	}

	if (!vch_plain(path, in_prefix))
		return false;

	int rv = vch_resolve(path, in_prefix, ctxt->follow, ctxt->current_path, sizeof(ctxt->current_path));
	if (rv >= 0)
	{
		if (rv == 1 && ctxt->current_path[0] == '/')
		{
			rv = 0;
			ctxt->current_path[0] = '\0';
		}
		ctxt->current_path_len = rv;
		*out_rv = 0;
		return true;
	}
	if (rv != -LINUX_ENOENT)
		return false;

	// the last component is missing (or a dangling symlink): resolve its directory, walk the last component
	char* slash = path + n;
	while (slash > path && *slash != '/')
		slash--;
	const char* last = slash + 1;
	if (*last == '\0' || slash == path)
		return false;
	*slash = '\0';
	char parent[4096];
	rv = vch_resolve(path, in_prefix, true, parent, sizeof(parent));
	if (rv < 0)
		return false;
	if (rv == 1 && parent[0] == '/')
	{
		rv = 0;
		parent[0] = '\0';
	}
	memcpy(ctxt->current_path, parent, rv + 1);
	ctxt->current_path_len = rv;
	if (in_prefix)
	{
		ctxt->current_root = prefix_path;
		ctxt->current_root_len = prefix_path_len;
	}
	else
	{
		ctxt->current_root = "";
		ctxt->current_root_len = 0;
	}
	*out_rv = vchroot_run(last, ctxt);
	return true;
}
#endif


int vchroot_expand(struct vchroot_expand_args* args)
{
	struct context ctxt;

#ifndef TEST
	if (prefix_path_len == -1)
		init_vchroot_path();
#endif

	ctxt.unknown_component = false;
	ctxt.symlink_depth = 0;
	ctxt.current_root = prefix_path;
	ctxt.current_root_len = prefix_path_len;
	ctxt.follow = !!(args->flags & VCHROOT_FOLLOW);

	const char* input_path = args->path;

	// x86Sim: "/.nofollow/<path>" (Darwin 23+) is <path> resolved without following symlinks (O_NOFOLLOW_ANY).
	// iOS 27's Foundation builds such paths (NSFileManager moves, nsurlsessiond's download hand-off, mobileassetd);
	// taken literally they landed in <prefix>/.nofollow/..., a tree nothing else sees (Siri/Spotlight assets never
	// reached mobileassetd's staging). Strip the prefix; the last component isn't followed.
	if (strncmp(input_path, "/.nofollow/", 11) == 0)
	{
		input_path += 10;
		ctxt.follow = false;
	}

	if (*input_path == '\0')
		return -LINUX_ENOENT;

	if (*input_path != '/')
	{
		char buf[50];

		if (args->dfd != -100)
			__simple_sprintf(buf, "/proc/self/fd/%d", args->dfd);
		else
			strcpy(buf, "/proc/self/cwd");

		#if defined(__NR_readlink)
			int rv = LINUX_SYSCALL(__NR_readlink, buf, ctxt.current_path, sizeof(ctxt.current_path) - 1);
		#else
			int rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, buf, ctxt.current_path, sizeof(ctxt.current_path) - 1);
		#endif

		if (rv < 0)
			return rv;
		
		// If we got "/", then turn it into "", because our algorithm will add a trailing slash later
		if (rv == 1 && ctxt.current_path[0] == '/')
		{
			ctxt.current_path[0] = '\0';
			ctxt.current_path_len = 0;
		}
		else
		{
			ctxt.current_path_len = rv;
			ctxt.current_path[rv] = '\0';
		}

		// Are we outside the vchrooted area already?
		if (ctxt.current_path_len < ctxt.current_root_len || strncmp(ctxt.current_path, ctxt.current_root, ctxt.current_root_len) != 0)
		{
			ctxt.current_root = "";
			ctxt.current_root_len = 0;
		}
	}

	int rv;
#ifndef TEST
	if (!vchroot_fast(&ctxt, input_path, &rv)) // x86Sim
#endif
		rv = vchroot_run(input_path, &ctxt);
	if (ctxt.current_path_len > 0)
		strcpy(args->path, ctxt.current_path);
	else
		strcpy(args->path, "/");

	return rv;
}

static int vchroot_run(const char* input_path, struct context* ctxt)
{
	if (ctxt->symlink_depth > MAX_SYMLINK_DEPTH)
		return -LINUX_ELOOP;

	if (*input_path == '/')
	{
		strcpy(ctxt->current_path, ctxt->current_root);
		ctxt->current_path_len = strlen(ctxt->current_path);
		input_path++;
	}

	const char* end;
	while (next_component(input_path, &end))
	{
		const unsigned int len = end - input_path;

		if ((len == 1 && input_path[0] == '.') || len == 0) // . or nothing (//)
		{
			// nothing to do
		}
		else
		{
			// append /
			ctxt->current_path[ctxt->current_path_len++] = '/';
			ctxt->current_path[ctxt->current_path_len] = '\0';

			if (len == 2 && input_path[0] == '.' && input_path[1] == '.') // ..
			{
				// Returning back into the vchrooted area
				if (ctxt->current_path_len <= 1)
				{
					strcpy(ctxt->current_path, prefix_path);
					strcat(ctxt->current_path, EXIT_PATH);
					ctxt->current_path_len = prefix_path_len + sizeof(EXIT_PATH);

					ctxt->current_path[ctxt->current_path_len-1] = '/';
					ctxt->current_path[ctxt->current_path_len] = '\0';

					ctxt->current_root = prefix_path;
					ctxt->current_root_len = prefix_path_len;
				}

				// current_path always ends with a slash
				// p points before the last /
				char* p = ctxt->current_path + ctxt->current_path_len - 2;

				while (true)
				{
					if (*p == '/')
					{
						*p = '\0';
						ctxt->current_path_len = p - ctxt->current_path;

						// We cannot exit current_root via ..
						if (ctxt->current_path_len < ctxt->current_root_len)
							return -LINUX_ENOENT;
						break;
					}
					p--;
				}
			}
			else
			{
				if (len + ctxt->current_path_len + 2 > sizeof(ctxt->current_path))
					return -LINUX_ENOENT;
				
				// Append the component
				const int prevlen = ctxt->current_path_len;

				memcpy(ctxt->current_path + ctxt->current_path_len, input_path, len);
				ctxt->current_path_len += len;
				ctxt->current_path[ctxt->current_path_len] = '\0';

				// Only analyze the last path component if we haven't had an unresolvent ENOENT before
				if (!ctxt->unknown_component)
				{
					stat_t st;
					#if defined(__NR_lstat)
						int status = LINUX_SYSCALL(__NR_lstat, ctxt->current_path, &st);
					#else
						#if __NR_newfstatat
							int status = LINUX_SYSCALL(__NR_newfstatat, LINUX_AT_FDCWD, ctxt->current_path, &st, LINUX_AT_SYMLINK_NOFOLLOW);
						#else
							int status = LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, ctxt->current_path, &st, LINUX_AT_SYMLINK_NOFOLLOW);
						#endif
					#endif

					if (icase_enabled && status == -LINUX_ENOENT)
					{
						// Case insensitive search

						// Examine the directory above
						ctxt->current_path[prevlen-1] = '\0';
						
						#if defined(__NR_open)
							int dfd = LINUX_SYSCALL(__NR_open, (prevlen > 1) ? ctxt->current_path : "/", LINUX_O_RDONLY);
						#else
							int dfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, (prevlen > 1) ? ctxt->current_path : "/", LINUX_O_RDONLY);
						#endif
						char dirents[4096]; // buffer space for struct linux_dirent64 entries
						int len;

						if (dfd < 0)
						{
							ctxt->unknown_component = true;
							goto done_getdents;
						}
						
						// Get a batch of directory entries
						while ((len = LINUX_SYSCALL(__NR_getdents64, dfd, dirents, sizeof(dirents))) > 0)
						{
							int pos = 0;

							// Iterate through directory entries
							while (pos < len)
							{
								struct linux_dirent64* de = (struct linux_dirent64*) &dirents[pos];
								if (strcasecmp(de->d_name, ctxt->current_path + prevlen) == 0)
								{
									// Fix up the case and be done with it
									strcpy(ctxt->current_path + prevlen, de->d_name);
									goto done_getdents;
								}
								pos += de->d_reclen;
							}
						}
						ctxt->unknown_component = true;
done_getdents:
						// Restore the / we removed a few lines above
						ctxt->current_path[prevlen-1] = '/';
						LINUX_SYSCALL(__NR_close, dfd);
					}
					else if (status == 0 && (st.st_mode & LINUX_S_IFMT) == LINUX_S_IFLNK)
					{
						// Follow symlink if follow is true or if we haven't reached the end of the input path yet
						if (ctxt->follow || *end)
						{
							char link[512];
							int rv;

							#if defined(__NR_readlink)
								rv = LINUX_SYSCALL(__NR_readlink, ctxt->current_path, link, sizeof(link) - 1);
							#else
								rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, ctxt->current_path, link, sizeof(link) - 1);
							#endif

							if (rv < 0)
								return rv;

							link[rv] = '\0';

							// https://github.com/darlinghq/darling/issues/916
							// Special procfs hack due to the presence of broken symlinks in /proc/xxx/fd/ used to
							// point to sockets, pipes or anonymous inodes.
							if (strncmp(ctxt->current_path, "/proc", 5) == 0)
							{
								if (strchr(link, ':') != 0)
								{
									goto ignore_symlink;
								}
							}

							// Remove the last component (because it will be substituted with symlink contents)
							if (link[0] != '/') // Only bother to do that if we know that the symlink is not absolute
							{
								ctxt->current_path_len = prevlen - 1; // kill the last slash as well
								ctxt->current_path[ctxt->current_path_len] = '\0';
							}

							// Symbolic link resolution
							const bool orig_follow = ctxt->follow;

							ctxt->follow = true;
							ctxt->symlink_depth++;

							// resolve absolute symlinks within the prefix
							//
							// however, DON'T resolve `/proc` symlinks within the prefix.
							// anything under `/proc` is from Linux's `/proc` since we bind-mount it, so we can special-case them because we want those to be Linux-root relative.
							// see https://github.com/darlinghq/darling/issues/1052 for the issue this works around.
							//
							// symlinks found after leaving the prefix through /Volumes/SystemRoot
							// (current_root is empty) are host symlinks, so they stay relative
							// to the host root (e.g. /etc/resolv.conf -> /run/...).
							if (link[0] == '/' && ctxt->current_root_len > 0 && !(strncmp(link, "/proc/", 6) == 0 || (rv == 5 && strncmp(link, "/proc", 5) == 0))) {
								ctxt->current_root = prefix_path;
								ctxt->current_root_len = prefix_path_len;
							}

							rv = vchroot_run(link, ctxt);

							ctxt->symlink_depth--;
							ctxt->follow = orig_follow;

							if (rv != 0)
								return rv;
						}
					}
				}

ignore_symlink:

				if (ctxt->current_root_len > 0 && ctxt->current_path_len - ctxt->current_root_len == sizeof(EXIT_PATH)-1)
				{
					if (strncasecmp_l(ctxt->current_path + ctxt->current_root_len, EXIT_PATH, sizeof(EXIT_PATH) - 1, LC_C_LOCALE) == 0)
					{
						// Switch to the real system root
						ctxt->current_path[0] = '\0';
						ctxt->current_path_len = 0;
						ctxt->current_root = "";
						ctxt->current_root_len = 0;
					}
				}
			}
		}

		// Move on to the next component
		input_path = end;
		while (*input_path == '/')
			input_path++;
	}

	return 0;
}

static bool next_component(const char* from, const char** end)
{
	const char* pos = from;
	while (*pos != '/' && *pos)
		pos++;
	*end = pos;
	return *from;
}

int vchroot_fdpath(struct vchroot_fdpath_args* args)
{
#ifndef TEST
	if (prefix_path_len == -1)
		init_vchroot_path();
#endif

	char buf[50];
	char link[4096];

	__simple_sprintf(buf, "/proc/self/fd/%d", args->fd);

	#if defined(__NR_readlink)
		int rv = LINUX_SYSCALL(__NR_readlink, buf, link, sizeof(link) - 1);
	#else
		int rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, buf, link, sizeof(link) - 1);
	#endif
	if (rv < 0)
		return rv;

	link[rv] = '\0';

	if (rv >= prefix_path_len && strncmp(link, prefix_path, prefix_path_len) == 0)
	{
		if (args->maxlen-1 < rv - prefix_path_len)
			return -LINUX_ENAMETOOLONG;
		strcpy(args->path, link + prefix_path_len);

		if (args->path[0] == '\0')
			strcpy(args->path, "/");
	}
	else
	{
		if (args->maxlen < sizeof(EXIT_PATH) + rv)
			return -LINUX_ENAMETOOLONG;

		memcpy(args->path, EXIT_PATH, sizeof(EXIT_PATH) - 1);
		memcpy(args->path + sizeof(EXIT_PATH) - 1, link, rv+1);
	}

	return 0;
}

int vchroot_unexpand(struct vchroot_unexpand_args* args)
{
	if (memcmp(args->path, prefix_path, prefix_path_len) == 0)
	{
		int bytes = strlen(args->path + prefix_path_len) + 1;
		memmove(args->path, args->path + prefix_path_len, bytes);

		if (args->path[0] == '\0')
			strcpy(args->path, "/");
	}
	else
	{
		int bytes = strlen(args->path) + 1;
		memmove(args->path + sizeof(EXIT_PATH) - 1, args->path, bytes);
		memcpy(args->path, EXIT_PATH, sizeof(EXIT_PATH) - 1);
	}

	return 0;
}

#ifdef TEST
int main(int argc, const char** argv)
{
	if (argc != 3)
	{
		printf("Usage: vchroot_expand <vchroot_dir> <path_to_expand>\n");
		return 1;
	}

	int dfd = open(argv[1], O_RDONLY | O_DIRECTORY);
	__darling_vchroot(dfd);
	close(dfd);

	if (getenv("ICASE"))
		icase_enabled = true;

	struct vchroot_expand_args args;
	args.dfd = -100;
	strcpy(args.path, argv[2]);

	int rv = vchroot_expand(&args);
	printf("vchroot_expand() rv = %d\n", rv);
	printf("-> path = %s\n", args.path);

	if (rv == 0)
	{
		int fd = open(args.path, O_RDONLY);
		struct vchroot_fdpath_args fdpath_args;
		char buf[4096];

		fdpath_args.path = buf;
		fdpath_args.maxlen = sizeof(buf);
		fdpath_args.fd = fd;

		rv = vchroot_fdpath(&fdpath_args);

		printf("vchroot_fdpath() rv = %d\n", rv);
		if (rv >= 0)
			printf("-> path = %s\n", buf);

		close(fd);
	}
	
	return 0;
}
#endif
