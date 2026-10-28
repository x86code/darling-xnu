// x86Code: access_extended (syscall 284, libc's accessx_np). Foundation's atomic file
// replacement (-[NSFileManager replaceItemAtURL:...], used e.g. by lsd to save its
// CSStore databases) checks access with it; without it every save failed with ENOSYS,
// lsd never recorded its database seeding as complete and served clients (SpringBoard)
// a database without applications. Implemented like XNU's access_extended() on top of
// faccessat: per-descriptor results (0 or a BSD errno) go to results[].
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/access_extended.h>

#include <sys/errno.h>
#include <sys/unistd.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/faccessat.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>


#define ACCESSX_MAX_DESCRIPTORS 100
#define ACCESSX_MAX_TABLESIZE (16 * 1024)

static int accessx_one(const char* path, int flags)
{
	int mode = 0;
	long ret;

	if (flags & (R_OK | _READ_OK | _RATTR_OK | _REXT_OK | _RPERM_OK))
		mode |= R_OK;
	if (flags & (W_OK | _WRITE_OK | _APPEND_OK | _WATTR_OK | _WEXT_OK | _WPERM_OK | _CHOWN_OK))
		mode |= W_OK;
	if (flags & (X_OK | _EXECUTE_OK))
		mode |= X_OK;

	ret = sys_faccessat(get_perthread_wd(), path, mode, 0);
	if (ret < 0)
		return (int) -ret;

	if (flags & (_DELETE_OK | _RMFILE_OK))
	{
		// deleting needs write and search permission on the containing directory
		char parent[1024];
		unsigned long len = 0;
		while (path[len])
		{
			if (len + 1 >= sizeof(parent))
				return ENAMETOOLONG;
			parent[len] = path[len];
			len++;
		}
		parent[len] = 0;
		while (len > 1 && parent[len - 1] == '/')
			parent[--len] = 0;
		while (len > 0 && parent[len - 1] != '/')
			len--;
		if (len == 0)
		{
			parent[0] = '.';
			parent[1] = 0;
		}
		else
		{
			while (len > 1 && parent[len - 1] == '/')
				len--;
			parent[len] = 0;
		}
		ret = sys_faccessat(get_perthread_wd(), parent, W_OK | X_OK, 0);
		if (ret < 0)
			return (int) -ret;
	}
	return 0;
}

long sys_access_extended(void* entries, unsigned long size, int* results, int uid)
{
	const struct accessx_descriptor* desc = (const struct accessx_descriptor*) entries;
	const char* base = (const char*) entries;
	unsigned long count, i;
	const char* path = 0;

	if (size < sizeof(*desc) || size > ACCESSX_MAX_TABLESIZE || !entries || !results)
		return -EINVAL;

	// the first name follows the descriptor table, so its offset gives the table size
	count = desc[0].ad_name_offset / sizeof(*desc);
	if (count == 0 || count > ACCESSX_MAX_DESCRIPTORS || count * sizeof(*desc) > size
		|| desc[0].ad_name_offset % sizeof(*desc) != 0)
		return -EINVAL;

	for (i = 0; i < count; i++)
	{
		unsigned int off = desc[i].ad_name_offset;
		if (off != 0)
		{
			if (off < count * sizeof(*desc) || off >= size)
				return -EINVAL;
			path = base + off;
		}
		else if (!path)
			return -EINVAL;
		results[i] = accessx_one(path, desc[i].ad_flags);
	}
	return 0;
}
