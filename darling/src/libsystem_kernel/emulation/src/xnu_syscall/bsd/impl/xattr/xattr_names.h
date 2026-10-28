#ifndef X86CODE_XATTR_NAMES_H
#define X86CODE_XATTR_NAMES_H
// x86Code: Darwin extended attribute names have no namespace ("com.apple.FinderInfo", "ArchiveFilePromise_ReloadDate");
// Linux only lets unprivileged processes use "user.*" ones and fails anything else with EOPNOTSUPP (chronod could not
// write its widget archives, and ChronoServices' icon cache). Every Darwin name is stored as "user." + name; listing
// returns the "user." attributes without the prefix and hides the other Linux namespaces. A missing attribute is
// ENOATTR on Darwin (Linux: ENODATA).

#define XATTR_LINUX_PREFIX "user."
#define XATTR_LINUX_NAME_MAX 256
#define XATTR_BSD_ENOATTR 93
#define XATTR_LINUX_ENODATA 61
#define XATTR_LINUX_ERANGE 34

static inline int xattr_name_to_linux(const char* name, char* out)
{
	int i = 0, j;
	for (j = 0; XATTR_LINUX_PREFIX[j]; j++)
		out[i++] = XATTR_LINUX_PREFIX[j];
	for (j = 0; name[j]; j++) {
		if (i >= XATTR_LINUX_NAME_MAX - 1)
			return -1;
		out[i++] = name[j];
	}
	out[i] = 0;
	return 0;
}

// errno for a failed Linux xattr call (negative Linux errno) as a negative BSD errno
#define XATTR_ERR(ret) ((ret) == -XATTR_LINUX_ENODATA ? -XATTR_BSD_ENOATTR : errno_linux_to_bsd(ret))

// Linux name list (len bytes) -> Darwin list in out (size 0: just measure). Returns the length or -ERANGE (Linux).
static inline long xattr_list_to_bsd(const char* list, long len, char* out, unsigned long size)
{
	long total = 0;
	const long plen = sizeof(XATTR_LINUX_PREFIX) - 1;
	for (long i = 0; i < len; ) {
		long n = 0;
		while (i + n < len && list[i + n])
			n++;
		int user = n > plen;
		for (long k = 0; user && k < plen; k++)
			if (list[i + k] != XATTR_LINUX_PREFIX[k])
				user = 0;
		if (user) {
			long m = n - plen + 1;
			if (size) {
				if (total + m > (long) size)
					return -XATTR_LINUX_ERANGE;
				for (long k = 0; k < m; k++)
					out[total + k] = list[i + plen + k];
			}
			total += m;
		}
		i += n + 1;
	}
	return total;
}

#endif
