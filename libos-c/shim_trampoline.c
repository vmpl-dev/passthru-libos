/* Copyright (C) 2020 Texas A&M University
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
 * shim_trampoline.c
 *
 * This file contains the trampoline code for making the actual system calls.
 */

#include <shim_trampoline.h>

long int _syscall6(long int sys_no, long int __arg1, long int __arg2,
                   long int __arg3, long int __arg4, long int __arg5,
                   long int __arg6)
{
    unsigned long int resultvar;
    register long int _a6 __asm__ ("r9")  = __arg6;
    register long int _a5 __asm__ ("r8")  = __arg5;
    register long int _a4 __asm__ ("r10") = __arg4;
    register long int _a3 __asm__ ("rdx") = __arg3;
    register long int _a2 __asm__ ("rsi") = __arg2;
    register long int _a1 __asm__ ("rdi") = __arg1;

    __asm__ __volatile__ ("syscall\n\t"
                          : "=a" (resultvar)
                          : "0" (sys_no), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6)
                          : "memory", "cc", "r11", "cx");

    return (long int) resultvar;

}

long int _syscall5(long int sys_no, long int __arg1, long int __arg2,
                   long int __arg3, long int __arg4, long int __arg5)
{
    unsigned long int resultvar;
    register long int _a5 __asm__ ("r8")  = __arg5;
    register long int _a4 __asm__ ("r10") = __arg4;
    register long int _a3 __asm__ ("rdx") = __arg3;
    register long int _a2 __asm__ ("rsi") = __arg2;
    register long int _a1 __asm__ ("rdi") = __arg1;

    __asm__ __volatile__ ("syscall\n\t"
                          : "=a" (resultvar)
                          : "0" (sys_no), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)
                          : "memory", "cc", "r11", "cx");

    return (long int) resultvar;

}

long int _syscall4(long int sys_no, long int __arg1, long int __arg2,
                   long int __arg3, long int __arg4)
{
    unsigned long int resultvar;
    register long int _a4 __asm__ ("r10") = __arg4;
    register long int _a3 __asm__ ("rdx") = __arg3;
    register long int _a2 __asm__ ("rsi") = __arg2;
    register long int _a1 __asm__ ("rdi") = __arg1;

    __asm__ __volatile__ ("syscall\n\t"
                          : "=a" (resultvar)
                          : "0" (sys_no), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)
                          : "memory", "cc", "r11", "cx");

    return (long int) resultvar;
}

long int _syscall3(long int sys_no, long int __arg1, long int __arg2,
                   long int __arg3)
{
    unsigned long int resultvar;
    register long int _a3 __asm__ ("rdx") = __arg3;
    register long int _a2 __asm__ ("rsi") = __arg2;
    register long int _a1 __asm__ ("rdi") = __arg1;

    __asm__ __volatile__ ("syscall\n\t"
                          : "=a" (resultvar)
                          : "0" (sys_no), "r"(_a1), "r"(_a2), "r"(_a3)
                          : "memory", "cc", "r11", "cx");

    return (long int) resultvar;
}

long int _syscall2(long int sys_no, long int __arg1, long int __arg2)
{
    unsigned long int resultvar;
    register long int _a2 __asm__ ("rsi") = __arg2;
    register long int _a1 __asm__ ("rdi") = __arg1;

    __asm__ __volatile__ ("syscall\n\t"
                          : "=a" (resultvar)
                          : "0" (sys_no), "r"(_a1), "r"(_a2)
                          : "memory", "cc", "r11", "cx");

    return (long int) resultvar;
}

long int _syscall1(long int sys_no, long int __arg1)
{
    unsigned long int resultvar;
    register long int _a1 __asm__ ("rdi") = __arg1;

    __asm__ __volatile__ ("syscall\n\t"
                          : "=a" (resultvar)
                          : "0"(sys_no), "r"(_a1)
                          : "memory", "cc", "r11", "cx");

    return (long int) resultvar;
}

long int _syscall0(long int sys_no)
{
    unsigned long int resultvar;
    __asm__ __volatile__ ("syscall\n\t"
                          : "=a" (resultvar)
                          : "0"(sys_no)
                          : "memory", "cc", "r11", "cx");

    return (long int) resultvar;
}
