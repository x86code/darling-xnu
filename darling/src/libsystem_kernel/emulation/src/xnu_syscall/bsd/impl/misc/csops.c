#include <darling/emulation/xnu_syscall/bsd/impl/misc/csops.h>

#include <stdint.h>
#include <sys/codesign.h>
#include <string.h>

#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darlingserver/rpc.h>

/*
 * x86Sim: csops / csops_audittoken backed by the target's code signature.
 *
 * Darling has no code signing; this used to return empty data for everything, so
 * every process looked unsigned and without entitlements. iOS daemons decide what a
 * client may do from its entitlements (and identifier), so the signature embedded in
 * the target's executable is read here (LC_CODE_SIGNATURE of the x86_64 slice) and
 * served with XNU's copy-out rules (see csops_copy_token in bsd/kern/kern_proc.c).
 * Nothing is verified: CS_OPS_STATUS reports valid.
 *
 * iOS simulator binaries carry an empty entitlements plist in their signature; their
 * real entitlements are in the __TEXT,__entitlements (XML) and __TEXT,__ents_der
 * (DER) sections, which take precedence when present.
 */

#ifndef CS_OPS_DER_ENTITLEMENTS_BLOB
#define CS_OPS_DER_ENTITLEMENTS_BLOB 16
#endif
#ifndef CS_OPS_TEAMID
#define CS_OPS_TEAMID 14
#endif
#ifndef CS_SIGNED
#define CS_SIGNED 0x20000000
#endif

#define CS_SUPERBLOB_MAGIC          0xfade0cc0
#define CS_CODEDIRECTORY_MAGIC      0xfade0c02
#define CSSLOT_CODEDIRECTORY        0
#define CSSLOT_ENTITLEMENTS         5
#define CSSLOT_DER_ENTITLEMENTS     7

#define CSOPS_CDHASH_LEN 20

#define MH_MAGIC_64 0xfeedfacf
#define FAT_MAGIC   0xcafebabe
#define CPU_TYPE_X86_64 0x01000007
#define LC_CODE_SIGNATURE 0x1d
#define LC_SEGMENT_64 0x19
#define CSMAGIC_EMBEDDED_ENTITLEMENTS     0xfade7171
#define CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xfade7172

#define CSOPS_MAX_SIGNATURE (4 * 1024 * 1024)

extern long sys_getpid(void);

#define CSOPS_PROT_RW 3
#define CSOPS_MAP_ANON_PRIVATE 0x1002 // Darwin MAP_ANON | MAP_PRIVATE

static uint32_t be32(const void* p)
{
	const uint8_t* b = p;
	return ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) | ((uint32_t) b[2] << 8) | b[3];
}

static long pread_full(int fd, void* buf, unsigned long len, long long off)
{
	return LINUX_SYSCALL(__NR_pread64, fd, buf, len, off);
}

/*
 * Load the embedded signature (SuperBlob) of `pid`'s executable into memory
 * allocated with sys_mmap; *size gets its length. Returns 0, or a negative BSD errno.
 */
struct sim_ents
{
	long long off[2];  // file offsets of __entitlements, __ents_der (0: none)
	uint32_t size[2];
	int fd;            // open executable when sections were found, else -1
};

static long load_signature(int pid, uint8_t** sig, uint32_t* size, struct sim_ents* ents)
{
	char path[1024];
	uint64_t fullLength = 0;
	uint32_t hdr[8];
	long long slice = 0;
	int fd, rv;

	*sig = NULL;
	*size = 0;
	memset(ents, 0, sizeof(*ents));
	ents->fd = -1;

	rv = dserver_rpc_get_executable_path(pid, path, sizeof(path), &fullLength);
	if (rv != 0)
		return rv < 0 ? -ESRCH : -rv;

	fd = LINUX_SYSCALL(__NR_open, path, LINUX_O_RDONLY | LINUX_O_CLOEXEC, 0);
	if (fd < 0)
		return -ENOENT;

	rv = -ENOENT;
	if (pread_full(fd, hdr, 8, 0) != 8)
		goto out;

	if (be32(hdr) == FAT_MAGIC)
	{
		uint32_t n = be32(&hdr[1]), i;
		for (i = 0; i < n && i < 16; i++)
		{
			uint32_t arch[5];
			if (pread_full(fd, arch, sizeof(arch), 8 + i * sizeof(arch)) != sizeof(arch))
				goto out;
			if (be32(&arch[0]) == CPU_TYPE_X86_64)
			{
				slice = be32(&arch[2]);
				break;
			}
		}
		if (i == n || i == 16)
			goto out;
	}

	// mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
	if (pread_full(fd, hdr, 32, slice) != 32 || hdr[0] != MH_MAGIC_64)
		goto out;

	{
		uint32_t ncmds = hdr[4], i;
		long long off = slice + 32;
		for (i = 0; i < ncmds; i++)
		{
			uint32_t lc[4]; // cmd, cmdsize, dataoff, datasize
			if (pread_full(fd, lc, sizeof(lc), off) != sizeof(lc))
				goto out;
			if (lc[0] == LC_SEGMENT_64)
			{
				// segment_command_64: cmd, cmdsize, segname[16], 4x u64, 2x prot, nsects, flags
				char segname[16];
				uint32_t nsects, s;
				if (pread_full(fd, segname, 16, off + 8) == 16 && __builtin_memcmp(segname, "__TEXT", 7) == 0
					&& pread_full(fd, &nsects, 4, off + 64) == 4)
				{
					for (s = 0; s < nsects && s < 64; s++)
					{
						// section_64: sectname[16], segname[16], addr, size (u64), offset (u32), ...
						uint8_t sect[52];
						if (pread_full(fd, sect, sizeof(sect), off + 72 + s * 80) != sizeof(sect))
							break;
						int which = !__builtin_memcmp(sect, "__entitlements", 15) ? 0
							: !__builtin_memcmp(sect, "__ents_der", 11) ? 1 : -1;
						if (which >= 0)
						{
							uint64_t ssize;
							uint32_t soff;
							memcpy(&ssize, sect + 40, 8);
							memcpy(&soff, sect + 48, 4);
							if (ssize > 0 && ssize < CSOPS_MAX_SIGNATURE)
							{
								ents->off[which] = slice + soff;
								ents->size[which] = (uint32_t) ssize;
							}
						}
					}
				}
			}
			if (lc[0] == LC_CODE_SIGNATURE)
			{
				if (lc[3] < 12 || lc[3] > CSOPS_MAX_SIGNATURE)
					goto out;
				uint8_t* buf = (uint8_t*) sys_mmap(NULL, lc[3], CSOPS_PROT_RW, CSOPS_MAP_ANON_PRIVATE, -1, 0);
				if ((long) buf < 0 && (long) buf > -4096)
				{
					rv = -ENOMEM;
					goto out;
				}
				if (pread_full(fd, buf, lc[3], slice + lc[2]) != lc[3] || be32(buf) != CS_SUPERBLOB_MAGIC)
				{
					sys_munmap(buf, lc[3]);
					goto out;
				}
				*sig = buf;
				*size = lc[3];
				rv = 0;
				goto out;
			}
			if (lc[1] < 8)
				goto out;
			off += lc[1];
		}
	}

out:
	ents->fd = -1;
	if (ents->off[0] || ents->off[1])
	{
		ents->fd = fd; // the caller reads the sections and closes it
		if (rv == -ENOENT)
			rv = 0;
		return rv;
	}
	LINUX_SYSCALL(__NR_close, fd);
	return rv;
}

// Copy an entitlements section out as a blob (magic, big-endian length, contents)
static long copy_sim_ents(struct sim_ents* ents, int which, void* useraddr, size_t usersize)
{
	uint32_t length = ents->size[which] + 8;
	uint8_t fakeheader[8] = { 0 };

	if (usersize < sizeof(fakeheader))
		return -ERANGE;
	uint32_t bemagic = __builtin_bswap32(which ? CSMAGIC_EMBEDDED_DER_ENTITLEMENTS : CSMAGIC_EMBEDDED_ENTITLEMENTS);
	uint32_t belen = __builtin_bswap32(length);
	if (usersize < length)
	{
		memcpy(&fakeheader[4], &belen, 4);
		memcpy(useraddr, fakeheader, sizeof(fakeheader));
		return -ERANGE;
	}
	memcpy(useraddr, &bemagic, 4);
	memcpy((uint8_t*) useraddr + 4, &belen, 4);
	if (pread_full(ents->fd, (uint8_t*) useraddr + 8, ents->size[which], ents->off[which]) != ents->size[which])
		return -EIO;
	return 0;
}

// Find a blob in the SuperBlob by slot type; returns its address (and length) or NULL
static const uint8_t* find_slot(const uint8_t* sig, uint32_t size, uint32_t slot, uint32_t* length)
{
	uint32_t count = be32(sig + 8), i;

	for (i = 0; i < count && 12 + (i + 1) * 8 <= size; i++)
	{
		uint32_t type = be32(sig + 12 + i * 8);
		uint32_t offset = be32(sig + 12 + i * 8 + 4);
		if (type != slot)
			continue;
		if (offset + 8 > size)
			return NULL;
		*length = be32(sig + offset + 4);
		if (*length < 8 || offset + *length > size)
			return NULL;
		return sig + offset;
	}
	return NULL;
}

// XNU's csops_copy_token: a missing blob is an all-zero 8-byte header; a short buffer
// gets a header carrying the needed length, and ERANGE
static long copy_token(const void* start, uint32_t length, void* useraddr, size_t usersize)
{
	uint8_t fakeheader[8] = { 0 };

	if (usersize < sizeof(fakeheader))
		return -ERANGE;
	if (start == NULL)
	{
		memcpy(useraddr, fakeheader, sizeof(fakeheader));
		return 0;
	}
	if (usersize < length)
	{
		uint32_t belen = __builtin_bswap32(length);
		memcpy(&fakeheader[4], &belen, sizeof(belen));
		memcpy(useraddr, fakeheader, sizeof(fakeheader));
		return -ERANGE;
	}
	memcpy(useraddr, start, length);
	return 0;
}

// CodeDirectory identifier / team id (XNU copies out an 8-byte header, then the string)
static long copy_cd_string(const uint8_t* sig, uint32_t size, int team, void* useraddr, size_t usersize)
{
	uint32_t cdlen;
	const uint8_t* cd = find_slot(sig, size, CSSLOT_CODEDIRECTORY, &cdlen);
	uint32_t stroff;
	const char* str;
	uint32_t len;
	uint8_t fakeheader[8] = { 0 };

	if (cd == NULL || be32(cd) != CS_CODEDIRECTORY_MAGIC || cdlen < 52)
		return -ENOENT;
	if (team)
	{
		// teamOffset exists from CodeDirectory version 0x20200
		if (be32(cd + 8) < 0x20200)
			return -ENOENT;
		stroff = be32(cd + 48);
	}
	else
		stroff = be32(cd + 20); // identOffset
	if (stroff == 0 || stroff >= cdlen)
		return -ENOENT;

	str = (const char*) cd + stroff;
	len = strlen(str) + 1;
	if (stroff + len > cdlen)
		return -ENOENT;

	uint32_t belen = __builtin_bswap32(len + sizeof(fakeheader));
	memcpy(&fakeheader[4], &belen, sizeof(belen));
	if (usersize < sizeof(fakeheader))
		return -ERANGE;
	memcpy(useraddr, fakeheader, sizeof(fakeheader));
	if (usersize < len + sizeof(fakeheader))
		return -ERANGE;
	memcpy((uint8_t*) useraddr + sizeof(fakeheader), str, len);
	return 0;
}

/*
 * Status flags as XNU sets them for a validly signed process (seen for a simulator
 * process on a Mac: CS_SIGNED | CS_DYLD_PLATFORM | CS_KILL | CS_VALID), plus
 * CS_PLATFORM_BINARY for Apple-signed code (CodeDirectory platform field set) and
 * CS_ENTITLEMENTS_VALIDATED when there are entitlements. containermanagerd requires
 * CS_VALID of its clients.
 */
#define CSF_KILL                 0x00000200
#define CSF_ENTITLEMENTS_VALIDATED 0x00004000
#define CSF_DYLD_PLATFORM        0x02000000
#define CSF_PLATFORM_BINARY      0x04000000
#define CSF_PLATFORM_PATH        0x08000000

// x86Sim: is the path inside a simulator runtime ("/RuntimeRoot/")?
static int in_runtime_root(const char* path)
{
	static const char needle[] = "/RuntimeRoot/";
	for (; *path; path++)
	{
		int i = 0;
		while (needle[i] && path[i] == needle[i])
			i++;
		if (!needle[i])
			return 1;
	}
	return 0;
}

static uint32_t status_for(int pid)
{
	uint8_t* sig = NULL;
	uint32_t sigsize = 0, cdlen = 0, flags;
	struct sim_ents ents;
	const uint8_t* cd;

	long lr = load_signature(pid, &sig, &sigsize, &ents);
	if (lr < 0 || sig == NULL)
	{
		/*
		 * x86Sim: the simulator runtime's binaries carry no code signature (entitlements
		 * sit in __TEXT,__entitlements), yet on a Mac they run as platform binaries
		 * (launchctl procinfo of SpringBoard: valid, kill, platform dyld, entitlements
		 * validated, platform binary). RunningBoard strips restricted entitlements of
		 * anything else, and SpringBoard could not launch WidgetRenderer_Default.
		 */
		char path[1024];
		uint64_t full = 0;
		flags = CS_VALID | CS_SIGNED; // unsigned: what Darling always reported
		if (lr >= 0 && dserver_rpc_get_executable_path(pid, path, sizeof(path), &full) == 0 && in_runtime_root(path))
		{
			flags |= CSF_KILL | CSF_DYLD_PLATFORM | CSF_PLATFORM_BINARY;
			if (ents.fd >= 0)
				flags |= CSF_ENTITLEMENTS_VALIDATED;
		}
		if (ents.fd >= 0)
			LINUX_SYSCALL(__NR_close, ents.fd);
		return flags;
	}

	flags = CS_VALID | CS_SIGNED | CSF_KILL | CSF_DYLD_PLATFORM;
	cd = find_slot(sig, sigsize, CSSLOT_CODEDIRECTORY, &cdlen);
	char rpath[1024];
	uint64_t rfull = 0;
	// x86Sim: simulator runtime binaries are ad-hoc signed without the platform field, yet run as
	// platform binaries on a Mac (see the unsigned case above)
	if ((cd != NULL && cdlen > 38 && cd[38] != 0) // CS_CodeDirectory.platform
		|| (dserver_rpc_get_executable_path(pid, rpath, sizeof(rpath), &rfull) == 0 && in_runtime_root(rpath)))
		// x86Sim: not CS_PLATFORM_PATH (a real simulator's SpringBoard has only "platform binary",
		// launchctl procinfo): RunningBoard strips restricted entitlements (primitiveattribute, ...)
		// unless (status & (PLATFORM_PATH|PLATFORM_BINARY|VALID)) == PLATFORM_BINARY|VALID, so
		// SpringBoard could not launch WidgetRenderer_Default (widgets stayed "Waiting...")
		flags |= CSF_PLATFORM_BINARY;
	if (ents.fd >= 0 || find_slot(sig, sigsize, CSSLOT_ENTITLEMENTS, &cdlen) != NULL)
		flags |= CSF_ENTITLEMENTS_VALIDATED;

	if (ents.fd >= 0)
		LINUX_SYSCALL(__NR_close, ents.fd);
	sys_munmap(sig, sigsize);
	return flags;
}

long sys_csops(int pid, unsigned int ops, void* useraddr, size_t usersize) {
	uint8_t* sig = NULL;
	uint32_t sigsize = 0;
	long ret = 0;

	if (pid == 0)
		pid = sys_getpid();

	switch (ops) {
		case CS_OPS_STATUS: {
			if (usersize < sizeof(uint32_t))
				return -EINVAL;
			*(uint32_t*)useraddr = status_for(pid);
			return 0;
		}

		case CS_OPS_CDHASH:
		case CS_OPS_BLOB:
		case CS_OPS_ENTITLEMENTS_BLOB:
		case CS_OPS_DER_ENTITLEMENTS_BLOB:
		case CS_OPS_IDENTITY:
		case CS_OPS_TEAMID:
			break;

		// all other operations are unsupported
		default:
			return -ENOSYS;
	}

	struct sim_ents ents;
	ret = load_signature(pid, &sig, &sigsize, &ents);
	if (ents.fd >= 0 && (ops == CS_OPS_ENTITLEMENTS_BLOB || ops == CS_OPS_DER_ENTITLEMENTS_BLOB))
	{
		int which = ops == CS_OPS_DER_ENTITLEMENTS_BLOB;
		ret = ents.off[which] ? copy_sim_ents(&ents, which, useraddr, usersize)
			: copy_token(NULL, 0, useraddr, usersize);
		LINUX_SYSCALL(__NR_close, ents.fd);
		if (sig)
			sys_munmap(sig, sigsize);
		return ret;
	}
	if (ents.fd >= 0)
		LINUX_SYSCALL(__NR_close, ents.fd);
	if (sig == NULL && ret >= 0)
		ret = -ENOENT;
	if (ret == -ENOENT && (ops == CS_OPS_BLOB || ops == CS_OPS_ENTITLEMENTS_BLOB || ops == CS_OPS_DER_ENTITLEMENTS_BLOB))
		return copy_token(NULL, 0, useraddr, usersize); // unsigned: no blob
	if (ret < 0)
		return ret;

	switch (ops) {
		case CS_OPS_CDHASH: {
			/*
			 * Not the real (SHA) cdhash, but derived from the CodeDirectory, so it is
			 * stable per binary and differs between binaries. Daemons cache clients'
			 * code signing info by cdhash; an all-zero hash made every client share
			 * one cache entry (containermanagerd then refused lsd).
			 */
			uint32_t cdlen = 0;
			const uint8_t* cd = find_slot(sig, sigsize, CSSLOT_CODEDIRECTORY, &cdlen);
			uint8_t hash[24];
			if (usersize < CSOPS_CDHASH_LEN) {
				ret = -ERANGE;
				break;
			}
			if (cd == NULL) {
				ret = -ENOENT;
				break;
			}
			for (int round = 0; round < 3; round++) {
				uint64_t h = 0xcbf29ce484222325ULL ^ (uint64_t) round * 0x9e3779b97f4a7c15ULL;
				for (uint32_t i = 0; i < cdlen; i++)
					h = (h ^ cd[i]) * 0x100000001b3ULL;
				memcpy(&hash[round * 8], &h, 8);
			}
			memcpy(useraddr, hash, CSOPS_CDHASH_LEN);
			ret = 0;
			break;
		}
		case CS_OPS_BLOB:
			ret = copy_token(sig, sigsize, useraddr, usersize);
			break;
		case CS_OPS_ENTITLEMENTS_BLOB:
		case CS_OPS_DER_ENTITLEMENTS_BLOB: {
			uint32_t len = 0;
			const uint8_t* blob = find_slot(sig, sigsize,
				ops == CS_OPS_ENTITLEMENTS_BLOB ? CSSLOT_ENTITLEMENTS : CSSLOT_DER_ENTITLEMENTS, &len);
			ret = copy_token(blob, len, useraddr, usersize);
			break;
		}
		case CS_OPS_IDENTITY:
			ret = copy_cd_string(sig, sigsize, 0, useraddr, usersize);
			break;
		case CS_OPS_TEAMID:
			ret = copy_cd_string(sig, sigsize, 1, useraddr, usersize);
			break;
	}

	sys_munmap(sig, sigsize);
	return ret;
}

long sys_csops_audittoken(int pid, unsigned int ops, void* useraddr, size_t usersize, audit_token_t* audit_token) {
	// the audit token names the same process (val[5] is its pid)
	return sys_csops(pid, ops, useraddr, usersize);
}
