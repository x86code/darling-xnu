#ifndef _DARLING_EMULATION_FOREIGN_HOOK_H_
#define _DARLING_EMULATION_FOREIGN_HOOK_H_

// Hooks that Darling's libSystem provides by overriding weak symbols in
// libsystem_kernel must be looked up by name when running on a foreign
// libSystem (the iOS simulator runtime's); see darling_foreign_hook() in lkm.c.
//
// FOREIGN_HOOK(type, var, name) declares a pointer `var` of `type`, resolved
// once; it is NULL on Darling's own libSystem and in dyld.

#ifndef VARIANT_DYLD

void* darling_foreign_hook(const char* name);

// Set in the child of posix_spawn between fork and exec: the hooks (libkqueue_sim)
// take locks other parent threads may have held at fork time, so they are skipped.
extern int darling_in_spawn_child;

#define FOREIGN_HOOK(type, var, name) \
	static __typeof__(type) var##_cached; \
	static int var##_resolved; \
	if (!var##_resolved) { \
		var##_cached = (__typeof__(type)) darling_foreign_hook(name); \
		var##_resolved = 1; \
	} \
	__typeof__(type) var = darling_in_spawn_child ? (__typeof__(type)) 0 : var##_cached

#else

#define FOREIGN_HOOK(type, var, name) __typeof__(type) var = (__typeof__(type)) 0

#endif

#endif
