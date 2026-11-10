#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>

#include <sys/errno.h>
#include <sys/fcntl.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/fcntl/fcntl.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/socktables.h>

#ifndef O_NOFOLLOW
#   define O_NOFOLLOW 0x0100
#endif
#ifndef O_DIRECTORY
#   define O_DIRECTORY 0x100000
#endif
#ifndef MAXPATHLEN
#	define MAXPATHLEN 1024
#endif

int oflags_bsd_to_linux(int flags);
int oflags_linux_to_bsd(int flags);

extern int sprintf(char *str, const char *format, ...);
long sys_readlink(const char* path, char* buf, unsigned long bsize);

static short int flock_type_linux_to_bsd(short int linux) {
	switch (linux) {
		case LINUX_F_RDLCK: return F_RDLCK;
		case LINUX_F_WRLCK: return F_WRLCK;
		case LINUX_F_UNLCK: return F_UNLCK;
		default:            return -1;
	};
};

static short int flock_type_bsd_to_linux(short int bsd) {
	switch (bsd) {
		case F_RDLCK: return LINUX_F_RDLCK;
		case F_WRLCK: return LINUX_F_WRLCK;
		case F_UNLCK: return LINUX_F_UNLCK;
		default:      return -1;
	};
};

static int cmd_bsd_to_linux(int bsd) {
	switch (bsd) {
		case F_DUPFD:  return LINUX_F_DUPFD;
		case F_GETFD:  return LINUX_F_GETFD;
		case F_SETFD:  return LINUX_F_SETFD;
		case F_GETFL:  return LINUX_F_GETFL;
		case F_SETFL:  return LINUX_F_SETFL;
		case F_GETOWN: return LINUX_F_GETOWN;
		case F_SETOWN: return LINUX_F_SETOWN;
		case F_SETLK:  return LINUX_F_SETLK;
		case F_SETLKW: return LINUX_F_SETLKW;
		case F_GETLK:  return LINUX_F_GETLK;
		case F_DUPFD_CLOEXEC: return LINUX_F_DUPFD_CLOEXEC;
		// x86Sim: open file description locks. Apple's SQLite probes F_OFD_GETLK to pick its
		// locking style; EINVAL made it fall back to dot-file locking (a <db>.lock directory),
		// which goes stale when a process dies and then reports "database is locked" forever.
		case 90: return 37; // F_OFD_SETLK  -> LINUX_F_OFD_SETLK
		case 91: return 38; // F_OFD_SETLKW -> LINUX_F_OFD_SETLKW
		case 92: return 36; // F_OFD_GETLK  -> LINUX_F_OFD_GETLK
		default:       return -1;
	};
};

// x86Sim: F_SETLKWTIMEOUT (10) / F_OFD_SETLKWTIMEOUT (93): F_SETLKW / F_OFD_SETLKW that give up
// with ETIMEDOUT after a timeout (XNU lf_setlock). Linux has no timed locks: retry the
// non-blocking F_SETLK / F_OFD_SETLK until the lock is granted or the timeout passes.
// Apple's SQLite uses these whenever a busy timeout is set (unixFileLock, for the database
// and -shm locks); the EINVAL we returned became SQLITE_BUSY ("database is locked") at once,
// without any lock contention (SpringBoard: applicationState.db, ATX stores -> _exit(3)).
struct bsd_flocktimeout {
	struct bsd_flock fl;
	struct { long tv_sec; long tv_nsec; } timeout;
};

static long fcntl_lock_timeout(int fd, int cmd, struct bsd_flocktimeout* ft)
{
	struct linux_flock lf;
	struct { long tv_sec; long tv_nsec; } now, end, nap;
	int linux_cmd = (cmd == 93) ? 37 /* LINUX_F_OFD_SETLK */ : LINUX_F_SETLK;
	long ret, wait_ns = 1000000;

	lf.l_type = flock_type_bsd_to_linux(ft->fl.l_type);
	lf.l_whence = ft->fl.l_whence;
	lf.l_start = ft->fl.l_start;
	lf.l_len = ft->fl.l_len;
	lf.l_pid = 0;

	LINUX_SYSCALL(__NR_clock_gettime, 1 /* CLOCK_MONOTONIC */, &end);
	end.tv_sec += ft->timeout.tv_sec;
	end.tv_nsec += ft->timeout.tv_nsec;
	while (end.tv_nsec >= 1000000000) { end.tv_sec++; end.tv_nsec -= 1000000000; }

	for (;;)
	{
#ifdef __NR_fcntl64
		ret = LINUX_SYSCALL(__NR_fcntl64, fd, linux_cmd, &lf);
#else
		ret = LINUX_SYSCALL(__NR_fcntl, fd, linux_cmd, &lf);
#endif
		if (ret >= 0)
			return ret;
		if (ret != -LINUX_EAGAIN && ret != -LINUX_EACCES)
			return errno_linux_to_bsd(ret);

		LINUX_SYSCALL(__NR_clock_gettime, 1, &now);
		long left = (end.tv_sec - now.tv_sec) * 1000000000L + (end.tv_nsec - now.tv_nsec);
		if (left <= 0)
			return -ETIMEDOUT;

		if (wait_ns > left)
			wait_ns = left;
		nap.tv_sec = wait_ns / 1000000000L;
		nap.tv_nsec = wait_ns % 1000000000L;
		LINUX_SYSCALL(__NR_nanosleep, &nap, 0);
		if (wait_ns < 10000000)
			wait_ns *= 2;
	}
}

long sys_fcntl(int fd, int cmd, long arg)
{
	CANCELATION_POINT();
	return sys_fcntl_nocancel(fd, cmd, arg);
}

long sys_fcntl_nocancel(int fd, int cmd, long arg)
{
	int ret, linux_cmd = cmd_bsd_to_linux(cmd);
	long original_arg = arg;

	switch (cmd)
	{
		case F_CHECK_LV:
			return 0;
		case 10: // x86Sim: F_SETLKWTIMEOUT
		case 93: // x86Sim: F_OFD_SETLKWTIMEOUT
			return fcntl_lock_timeout(fd, cmd, (struct bsd_flocktimeout*) arg);
		// No code signing enforcement: accept signature registration (dyld_sim needs F_ADDFILESIGS_FOR_DYLD_SIM)
		case F_ADDFILESIGS:
		case F_ADDFILESIGS_RETURN:
		case F_ADDFILESIGS_FOR_DYLD_SIM:
		{
			// Like XNU, report the end of the signed range in fs_file_start;
			// claim everything up to the signature blob itself is covered
			fsignatures_t* sigs = (fsignatures_t*) arg;
			sigs->fs_file_start += (off_t)(uintptr_t) sigs->fs_blob_start;
			return 0;
		}
		case F_SETFD:
			if (arg & ~FD_CLOEXEC)
				return -EINVAL;
			break;
		case F_SETFL:
			arg = oflags_bsd_to_linux(arg);
			break;
		// x86Sim: data protection classes. Linux file systems have no data protection,
		// which is class D (PROTECTION_CLASS_D, "no protection"): report it, accept sets.
		case 63: // F_GETPROTECTIONCLASS
			return 4;
		case 64: // F_SETPROTECTIONCLASS
			return 0;
		case F_GETPATH:
		{
			ret = fdpath(fd, arg, MAXPATHLEN);
			if (ret < 0)
				return errno_linux_to_bsd(ret);

			return 0;
		}
		case F_SETLK:
		case F_SETLKW:
		case F_GETLK:
		case 90: case 91: case 92: { // x86Sim: F_OFD_SETLK/SETLKW/GETLK
			struct bsd_flock* bsd_struct = arg;
			struct linux_flock* linux_struct = __builtin_alloca(sizeof(struct linux_flock));
			linux_struct->l_type = flock_type_bsd_to_linux(bsd_struct->l_type);
			linux_struct->l_whence = bsd_struct->l_whence;
			linux_struct->l_start = bsd_struct->l_start;
			linux_struct->l_len = bsd_struct->l_len;
			// x86Sim: Linux rejects OFD lock requests with a nonzero l_pid
			linux_struct->l_pid = (cmd >= 90) ? 0 : bsd_struct->l_pid;
			arg = linux_struct;
		} break;
		// x86Sim (Speed 27): F_PREALLOCATE (struct fstore): reserve space without changing the file's size, as
		// Linux's fallocate(FALLOC_FL_KEEP_SIZE). It was EINVAL: Core ML's BNNS graph compiler ("failed to preallocate
		// file") failed, so Spotlight's query parser couldn't load its model in time and Spotlight crashed on typing.
		// A file system without fallocate gets XNU's answer for space it doesn't have to reserve: all of it.
		case 42: {
			struct bsd_fstore {
				unsigned int fst_flags;
				int fst_posmode;
				long long fst_offset;
				long long fst_length;
				long long fst_bytesalloc;
			}* fst = (struct bsd_fstore*) arg;
			long long off;
			if (fst == NULL || fst->fst_length < 0)
				return -EINVAL;
			fst->fst_bytesalloc = 0;
			if (fst->fst_posmode == 3) { // F_PEOFPOSMODE: from the end of the file
				long long end = LINUX_SYSCALL(__NR_lseek, fd, 0, 2 /* SEEK_END */);
				if (end < 0)
					return errno_linux_to_bsd(end);
				off = end + fst->fst_offset;
			} else if (fst->fst_posmode == 4) { // F_VOLPOSMODE
				off = fst->fst_offset;
			} else {
				return -EINVAL;
			}
			if (off < 0)
				return -EINVAL;
			if (fst->fst_length == 0)
				return 0;
			ret = LINUX_SYSCALL(__NR_fallocate, fd, 1 /* FALLOC_FL_KEEP_SIZE */, off, fst->fst_length);
			if (ret < 0 && ret != -LINUX_EOPNOTSUPP && ret != -LINUX_ENOSYS)
				return errno_linux_to_bsd(ret);
			fst->fst_bytesalloc = fst->fst_length;
			return 0;
		}
		// x86Sim (Speed 27): read-ahead and caching hints (XNU: per-file flags): Linux's page cache advice
		case 45: // F_RDAHEAD
			LINUX_SYSCALL(__NR_fadvise64, fd, 0, 0, arg ? 2 /* POSIX_FADV_SEQUENTIAL */ : 0 /* NORMAL */);
			return 0;
		case 44: { // F_RDADVISE (struct radvisory: offset, count): read the range ahead
			struct { long long ra_offset; int ra_count; }* ra = (void*) arg;
			if (ra == NULL || ra->ra_offset < 0 || ra->ra_count < 0)
				return -EINVAL;
			LINUX_SYSCALL(__NR_fadvise64, fd, ra->ra_offset, ra->ra_count, 3 /* POSIX_FADV_WILLNEED */);
			return 0;
		}
		// F_SETCONFINED / F_GETCONFINED (95, 96): a confined descriptor may not be sent to another process (SQLite
		// sets it on its database files). Nothing sends descriptors behind a program's back here: accepted, never set.
		case 95:
			return 0;
		case 96:
			return 0;
		case 48: // F_NOCACHE
			if (arg)
				LINUX_SYSCALL(__NR_fadvise64, fd, 0, 0, 4 /* POSIX_FADV_DONTNEED */);
			return 0;
		// F_BARRIERFSYNC: the writes before it reach the disk before those after: fdatasync gives at least that
		case 85:
			ret = LINUX_SYSCALL1(__NR_fdatasync, fd);
			return ret < 0 ? errno_linux_to_bsd(ret) : 0;
		// F_PUNCHHOLE (struct fpunchhole: flags, reserved, offset, length): deallocate, keeping the size
		case 99: {
			struct { unsigned int fp_flags; unsigned int reserved; long long fp_offset; long long fp_length; }* ph = (void*) arg;
			if (ph == NULL || ph->fp_flags != 0 || ph->fp_offset < 0 || ph->fp_length < 0)
				return -EINVAL;
			ret = LINUX_SYSCALL(__NR_fallocate, fd, 3 /* FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE */,
				ph->fp_offset, ph->fp_length);
			return ret < 0 ? errno_linux_to_bsd(ret) : 0;
		}
		// F_GETPATH_NOFIRMLINK: there are no firmlinks here
		case 102:
			ret = fdpath(fd, arg, MAXPATHLEN);
			return ret < 0 ? errno_linux_to_bsd(ret) : 0;
		case F_FULLFSYNC: {
			ret = LINUX_SYSCALL1(__NR_fsync, fd);
			if (ret < 0)
				ret = errno_linux_to_bsd(ret);
			return 0;
		};
		// TODO: implement remaining commands
		default:
			if (linux_cmd == -1)
				return -EINVAL;
	}

#ifdef __NR_fcntl64
	ret = LINUX_SYSCALL(__NR_fcntl64, fd, linux_cmd, arg);
#else
	ret = LINUX_SYSCALL(__NR_fcntl, fd, linux_cmd, arg);
#endif
	if (ret < 0)
	{
		ret = errno_linux_to_bsd(ret);
		return ret;
	}

	switch (cmd)
	{
		case F_GETFL:
			ret = oflags_linux_to_bsd(ret);
			break;
		case F_SETLK:
		case F_SETLKW:
		case F_GETLK:
		case 90: case 91: case 92: { // x86Sim: F_OFD_SETLK/SETLKW/GETLK
			struct bsd_flock* bsd_struct = original_arg;
			struct linux_flock* linux_struct = arg;
			bsd_struct->l_type = flock_type_linux_to_bsd(linux_struct->l_type);
			bsd_struct->l_whence = linux_struct->l_whence;
			bsd_struct->l_start = linux_struct->l_start;
			bsd_struct->l_len = linux_struct->l_len;
			bsd_struct->l_pid = linux_struct->l_pid;
		} break;
		case F_DUPFD:
		case F_DUPFD_CLOEXEC:
			kqueue_dup(fd, ret);
			socket_tables_dup(fd, ret);
			break;
	}

	return ret;
}
