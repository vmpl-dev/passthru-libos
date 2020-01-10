#ifndef _SHIM_DEFS_H_
#define _SHIM_DEFS_H_

#define SYSCALLNR  340

#ifdef __x86_64__
# include "sysdep-x86_64.h"
#endif

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

#define __UNUSED(x) do { (void)(x); } while (0)

#endif
