#ifndef _DARLING_EMULATION_TSD_H_
#define _DARLING_EMULATION_TSD_H_

#include <pthread/tsd_private.h>

#define __PTK_DARLING_XTRACE_TLS          __PTK_DARLING_KEY0
#define __PTK_DARLING_PERTHREAD_WD_IS_SET __PTK_DARLING_KEY1
#define __PTK_DARLING_PERTHREAD_WD_FD     __PTK_DARLING_KEY2
#define __PTK_DARLING_WQ_ENTRY_SP        __PTK_DARLING_KEY3 // x86Code: rsp at a workqueue thread's first entry
#define __PTK_DARLING_WQ_FLAGS           __PTK_DARLING_KEY4 // x86Code: WQ_FLAG_THREAD_* of a workqueue thread's current run
#define __PTK_DARLING_IOPOL              __PTK_DARLING_KEY5 // x86Code: the thread's iopolicysys policies (4 bits per type)
// other __PTK_DARLING_KEYs are currently unused

#endif // _DARLING_EMULATION_TSD_H_
