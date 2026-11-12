/*
 * iOS simulator (iOS 26) compatibility exports for libsystem_kernel.
 *
 * The simulator runtime re-exports the host's libsystem_kernel and expects
 * interfaces newer than Darling's macOS 11 XNU. Each one here is either
 * translated onto an older equivalent or stubbed as unsupported.
 */

#include <stdint.h>
#include <stddef.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <sys/errno.h>
#include <sys/types.h>

#define EXPORT __attribute__((visibility("default")))
#define LOW_32(v)  ((uint32_t)(v))
#define HIGH_32(v) ((uint32_t)((uint64_t)(v) >> 32))

extern int* __error(void);
extern int open(const char* path, int oflag, ...);
extern int openat(int fd, const char* path, int oflag, ...);
extern int mkfifo(const char* path, mode_t mode);
extern int mknod(const char* path, mode_t mode, dev_t dev);

/* --- mach_msg2 ---------------------------------------------------------- */

typedef uint64_t mach_msg_option64_t;

#define MACH64_MSG_VECTOR 0x0000000100000000ull

typedef struct {
	uint64_t msgv_data;
	uint64_t msgv_rcv_addr;
	uint32_t msgv_send_size;
	uint32_t msgv_rcv_size;
} sim_mach_msg_vector_t;

// Translate a mach_msg2 call onto the classic mach_msg_overwrite.
// Vector mode: vector 0 is the message, vector 1 (if any) the aux buffer.
// There is no aux data in this kernel, so a received aux header is zeroed.
EXPORT mach_msg_return_t mach_msg2_internal(void* data, mach_msg_option64_t option64,
	uint64_t msgh_bits_and_send_size, uint64_t msgh_remote_and_local_port,
	uint64_t msgh_voucher_and_id, uint64_t desc_count_and_rcv_name,
	uint64_t rcv_size_and_priority, uint64_t timeout)
{
	mach_msg_option_t option = (mach_msg_option_t) LOW_32(option64);
	mach_port_name_t rcv_name = HIGH_32(desc_count_and_rcv_name);
	mach_msg_header_t* msg;
	mach_msg_header_t* rcv_msg;
	mach_msg_size_t send_size, rcv_size;
	sim_mach_msg_vector_t* aux = NULL;

	if (option64 & MACH64_MSG_VECTOR)
	{
		sim_mach_msg_vector_t* vec = (sim_mach_msg_vector_t*) data;
		// x86Sim Platforms 1: in vector mode the send and receive "sizes" are vector counts (XNU's mach_msg2():
		// send_size in the high half of the third argument, rcv_size in the low half of the seventh). A receive-only
		// call passes 0 send vectors and 2 receive vectors (message + aux): counting the send half alone, the aux header
		// was never written and libdispatch's large-message receive (tvOS / watchOS 27) read stack garbage as its size
		// ("BUG IN LIBDISPATCH: Invalid msg aux data size" in launchd_sim, configd_sim, cfprefsd, ...).
		uint32_t count = HIGH_32(msgh_bits_and_send_size);
		if (LOW_32(rcv_size_and_priority) > count)
			count = LOW_32(rcv_size_and_priority);

		msg = (mach_msg_header_t*) vec[0].msgv_data;
		rcv_msg = vec[0].msgv_rcv_addr ? (mach_msg_header_t*) vec[0].msgv_rcv_addr : msg;
		send_size = vec[0].msgv_send_size;
		rcv_size = vec[0].msgv_rcv_size;
		if (count > 1)
			aux = &vec[1];
	}
	else
	{
		msg = rcv_msg = (mach_msg_header_t*) data;
		send_size = HIGH_32(msgh_bits_and_send_size);
		rcv_size = LOW_32(rcv_size_and_priority);
	}

	mach_msg_return_t mr = mach_msg_overwrite(msg, option, send_size, rcv_size, rcv_name,
		(mach_msg_timeout_t) timeout, MACH_PORT_NULL, rcv_msg, 0);

	if (aux && (option & MACH_RCV_MSG) && mr == MACH_MSG_SUCCESS)
	{
		void* aux_buf = (void*)(uintptr_t)(aux->msgv_rcv_addr ? aux->msgv_rcv_addr : aux->msgv_data);
		if (aux_buf && aux->msgv_rcv_size >= sizeof(uint32_t))
			*(uint32_t*) aux_buf = 0; // mach_msg_aux_header_t.msgdh_size: no aux data
	}
	return mr;
}

EXPORT void voucher_mach_msg_clear(mach_msg_header_t* msg)
{
	msg->msgh_voucher_port = MACH_PORT_NULL;
	msg->msgh_bits &= ~MACH_MSGH_BITS_VOUCHER_MASK;
}

/* --- eventlinks and work intervals (used by os_workgroup) --------------- */

// x86Sim: mach_eventlink_create / destroy / associate / disassociate are the MIG routines (libsyscall mach_eventlink.defs)
// now, served by darlingserver's XNU; they were KERN_NOT_SUPPORTED stubs here.

EXPORT int work_interval_instance_set_complexity(void* instance, uint8_t high, uint8_t low)
{
	return 0;
}

/* --- file system -------------------------------------------------------- */

#define SIM_AT_FDCWD -2

EXPORT int openat_authenticated_np(int fd, const char* path, int oflag, int authenticated_fd)
{
	return openat(fd, path, oflag, 0);
}

EXPORT int mkfifoat(int fd, const char* path, mode_t mode)
{
	if (fd != SIM_AT_FDCWD && path[0] != '/')
	{
		*__error() = ENOTSUP;
		return -1;
	}
	return mkfifo(path, mode);
}

EXPORT int mknodat(int fd, const char* path, mode_t mode, dev_t dev)
{
	if (fd != SIM_AT_FDCWD && path[0] != '/')
	{
		*__error() = ENOTSUP;
		return -1;
	}
	return mknod(path, mode, dev);
}

EXPORT int posix_spawnattr_setdataless_iopolicy_np(void* attr, int policy)
{
	return 0;
}

/* --- Skywalk channels (user-space networking): unsupported ------------- */

EXPORT void* os_channel_attr_create(void) { return NULL; }
EXPORT void os_channel_attr_destroy(void* attr) { }
EXPORT int os_channel_attr_get(void* attr, int type, uint64_t* value) { return ENOTSUP; }
EXPORT int os_channel_attr_set(void* attr, int type, uint64_t value) { return ENOTSUP; }
EXPORT void* os_channel_create_extended(const void* uuid, uint32_t port, int dir, int ring, void* attr) { return NULL; }
EXPORT int os_channel_get_fd(void* channel) { return -1; }
EXPORT int os_channel_read_attr(void* channel, void* attr) { return ENOTSUP; }
EXPORT void* os_channel_rx_ring(void* channel, uint32_t ring_id) { return NULL; }
EXPORT void* os_channel_tx_ring(void* channel, uint32_t ring_id) { return NULL; }
EXPORT uint32_t os_channel_ring_id(void* channel, int type) { return 0; }
EXPORT int os_channel_sync(void* channel, int mode) { return ENOTSUP; }
EXPORT void* os_channel_get_next_slot(void* ring, void* slot, void* prop) { return NULL; }
EXPORT int os_channel_advance_slot(void* ring, void* slot) { return ENOTSUP; }
EXPORT void os_channel_set_slot_properties(void* ring, void* slot, const void* prop) { }
