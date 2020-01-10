/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_syscalls.h
 */

#ifndef _SHIM_SYSCALLS_H_
#define _SHIM_SYSCALLS_H_

#include <shim_types.h>
#include <shim_defs.h>

#define SHIM_ARG_TYPE long

#define BEGIN_SHIM(name, args ...)                          \
    SHIM_ARG_TYPE __shim_##name(args) {                     \
        SHIM_ARG_TYPE ret = 0;

#define END_SHIM(name)                                      \
        return ret;                                         \
    }

#define DEFINE_SHIM_SYSCALL(name, n, func, ...)             \
    SHIM_SYSCALL_##n (name, func, __VA_ARGS__)              \
    EXPORT_SHIM_SYSCALL (name, n, __VA_ARGS__)

#define PROTO_ARGS_0() void
#define PROTO_ARGS_1(t, a) t a
#define PROTO_ARGS_2(t, a, rest ...) t a, PROTO_ARGS_1(rest)
#define PROTO_ARGS_3(t, a, rest ...) t a, PROTO_ARGS_2(rest)
#define PROTO_ARGS_4(t, a, rest ...) t a, PROTO_ARGS_3(rest)
#define PROTO_ARGS_5(t, a, rest ...) t a, PROTO_ARGS_4(rest)
#define PROTO_ARGS_6(t, a, rest ...) t a, PROTO_ARGS_5(rest)

#define CAST_ARGS_0()
#define CAST_ARGS_1(t, a) (SHIM_ARG_TYPE) a
#define CAST_ARGS_2(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_1(rest)
#define CAST_ARGS_3(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_2(rest)
#define CAST_ARGS_4(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_3(rest)
#define CAST_ARGS_5(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_4(rest)
#define CAST_ARGS_6(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_5(rest)

#define DEFINE_SHIM_FUNC(func, n, r, args ...)             \
    r func (PROTO_ARGS_##n (args));

#define TYPE_HASH(t) ({ const char * _s = #t;              \
       ((uint16_t) _s[0] << 8) +  _s[1]; })

#define POINTER_TYPE(t) ({ int _h = TYPE_HASH(t);                   \
       _h == TYPE_HASH(void *) || _h == TYPE_HASH(char *) ||        \
       _h == TYPE_HASH(const); })

#define EXPORT_SHIM_SYSCALL(name, n, r, args ...)                   \
    r shim_##name (PROTO_ARGS_##n (args)) {                         \
        SHIM_ARG_TYPE ret =  __shim_##name (CAST_ARGS_##n (args));  \
        if (POINTER_TYPE(r)) {                                      \
            if ((uint64_t) ret >= (uint64_t) -4095L) return (r) 0;  \
        } else {                                                    \
            if ((int) ret < 0) return (r) -1;                       \
        }                                                           \
        return (r) ret;                                             \
    }

#define PARSE_SYSCALL1(name, ...)                                   \
    if (debug_handle)                                               \
        parse_syscall_before(__NR_##name, #name, ##__VA_ARGS__);

#define PARSE_SYSCALL2(name, ...)                                   \
    if (debug_handle)                                               \
        parse_syscall_after(__NR_##name, #name, ##__VA_ARGS__);

void parse_syscall_before (int sysno, const char * name, int nr, ...);
void parse_syscall_after (int sysno, const char * name, int nr, ...);

#define SHIM_SYSCALL_0(name, func, r)                           \
    BEGIN_SHIM(name, void)                                      \
        PARSE_SYSCALL1(name, 0);                                \
        r __ret = (func)();                                     \
        PARSE_SYSCALL2(name, 0, #r, __ret);                     \
        ret = (SHIM_ARG_TYPE) __ret;                            \
    END_SHIM(name)

#define SHIM_SYSCALL_1(name, func, r, t1, a1)                               \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1)                                  \
        t1 a1 = (t1) __arg1;                                                \
        PARSE_SYSCALL1(name, 1, #t1, a1);                                   \
        r __ret = (func)(a1);                                               \
        PARSE_SYSCALL2(name, 1, #r, __ret, #t1, a1);                        \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_2(name, func, r, t1, a1, t2, a2)                       \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        PARSE_SYSCALL1(name, 2, #t1, a1, #t2, a2);                          \
        r __ret = (func)(a1, a2);                                           \
        PARSE_SYSCALL2(name, 2, #r, __ret, #t1, a1, #t2, a2);               \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_3(name, func, r, t1, a1, t2, a2, t3, a3)               \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3)                                  \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        PARSE_SYSCALL1(name, 3, #t1, a1, #t2, a2, #t3, a3);                 \
        r __ret = (func)(a1, a2, a3);                                       \
        PARSE_SYSCALL2(name, 3, #r, __ret, #t1, a1, #t2, a2, #t3, a3);      \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_4(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4)       \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        PARSE_SYSCALL1(name, 4, #t1, a1, #t2, a2, #t3, a3, #t4, a4);        \
        r __ret = (func)(a1, a2, a3, a4);                                   \
        PARSE_SYSCALL2(name, 4, #r, __ret, #t1, a1, #t2, a2, #t3, a3,       \
                       #t4, a4);                                            \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_5(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4,            \
                     SHIM_ARG_TYPE __arg5)                                  \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        t5 a5 = (t5) __arg5;                                                \
        PARSE_SYSCALL1(name, 5, #t1, a1, #t2, a2, #t3, a3, #t4, a4,         \
                       #t5, a5);                                            \
        r __ret = (func)(a1, a2, a3, a4, a5);                               \
        PARSE_SYSCALL2(name, 5, #r, __ret, #t1, a1, #t2, a2, #t3, a3,       \
                       #t4, a4, #t5, a5);                                   \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_6(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4,            \
                     SHIM_ARG_TYPE __arg5, SHIM_ARG_TYPE __arg6)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        t5 a5 = (t5) __arg5;                                                \
        t6 a6 = (t6) __arg6;                                                \
        PARSE_SYSCALL1(name, 6, #t1, a1, #t2, a2, #t3, a3, #t4, a4,         \
                       #t5, a5, #t6, a6);                                   \
        r __ret = (func)(a1, a2, a3, a4, a5, a6);                           \
        PARSE_SYSCALL2(name, 6, #r, __ret, #t1, a1, #t2, a2, #t3, a3,       \
                       #t4, a4, #t5, a5, #t6, a6);  \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_PROTO_ARGS_0 void
#define SHIM_PROTO_ARGS_1 SHIM_ARG_TYPE __arg1
#define SHIM_PROTO_ARGS_2 SHIM_PROTO_ARGS_1, SHIM_ARG_TYPE __arg2
#define SHIM_PROTO_ARGS_3 SHIM_PROTO_ARGS_2, SHIM_ARG_TYPE __arg3
#define SHIM_PROTO_ARGS_4 SHIM_PROTO_ARGS_3, SHIM_ARG_TYPE __arg4
#define SHIM_PROTO_ARGS_5 SHIM_PROTO_ARGS_4, SHIM_ARG_TYPE __arg5
#define SHIM_PROTO_ARGS_6 SHIM_PROTO_ARGS_5, SHIM_ARG_TYPE __arg6

#define SHIM_PASS_ARGS_1 __arg1
#define SHIM_PASS_ARGS_2 SHIM_PASS_ARGS_1, __arg2
#define SHIM_PASS_ARGS_3 SHIM_PASS_ARGS_2, __arg3
#define SHIM_PASS_ARGS_4 SHIM_PASS_ARGS_3, __arg4
#define SHIM_PASS_ARGS_5 SHIM_PASS_ARGS_4, __arg5
#define SHIM_PASS_ARGS_6 SHIM_PASS_ARGS_5, __arg6

#define SHIM_UNUSED_ARGS_0()

#define SHIM_UNUSED_ARGS_1() do {               \
        __UNUSED(__arg1);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_2() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_3() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_4() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
    } while (0)

#define SHIM_UNUSED_ARGS_5() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
        __UNUSED(__arg5);                       \
    } while (0)

#define SHIM_UNUSED_ARGS_6() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
        __UNUSED(__arg5);                       \
        __UNUSED(__arg6);                       \
    } while (0)

#define DO_SYSCALL(...) DO_SYSCALL2(__VA_ARGS__)
#define DO_SYSCALL2(n, ...) -ENOSYS

#define DO_SYSCALL_0(sysno) -ENOSYS
#define DO_SYSCALL_1(sysno, ...) DO_SYSCALL(1, sysno, SHIM_PASS_ARGS_1)
#define DO_SYSCALL_2(sysno, ...) DO_SYSCALL(2, sysno, SHIM_PASS_ARGS_2)
#define DO_SYSCALL_3(sysno, ...) DO_SYSCALL(3, sysno, SHIM_PASS_ARGS_3)
#define DO_SYSCALL_4(sysno, ...) DO_SYSCALL(4, sysno, SHIM_PASS_ARGS_4)
#define DO_SYSCALL_5(sysno, ...) DO_SYSCALL(5, sysno, SHIM_PASS_ARGS_5)
#define DO_SYSCALL_6(sysno, ...) DO_SYSCALL(6, sysno, SHIM_PASS_ARGS_6)

#define SHIM_SYSCALL_PASSTHROUGH(name, n, ...)                      \
    BEGIN_SHIM(name, SHIM_PROTO_ARGS_##n)                           \
        /* printf("WARNING: shim_" #name " not implemented\n"); */  \
        SHIM_UNUSED_ARGS_##n();                                     \
        ret = DO_SYSCALL_##n(__NR_##name);                          \
    END_SHIM(name)                                                  \
    EXPORT_SHIM_SYSCALL(name, n, __VA_ARGS__)

#endif /* _PAL_SYSCALLS_H_ */
