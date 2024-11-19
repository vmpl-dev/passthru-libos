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
#include <syscall_arch.h>

#if __GCC__ >= 12
#define vmgexit "vmgexit"
#else
#define vmgexit "rep; vmmcall"
#endif

long int _syscall0(long n)
{
	unsigned long ret;
	__syscall_wrapper(__volatile__(vmgexit : "=a"(ret) : "a"(n) : "rcx", "r11", "memory"),
					 __volatile__("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory"));
	return ret;
}

long int _syscall1(long n, long a1)
{
	unsigned long ret;
	__syscall_wrapper(__volatile__(vmgexit : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory"),
					 __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory"));
	return ret;
}

long int _syscall2(long n, long a1, long a2)
{
	unsigned long ret;
	__syscall_wrapper(__volatile__(vmgexit : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
								   : "rcx", "r11", "memory"),
					  __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
								   : "rcx", "r11", "memory"));
	return ret;
}

long int _syscall3(long n, long a1, long a2, long a3)
{
	unsigned long ret;
	__syscall_wrapper(__volatile__(vmgexit : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														   "d"(a3) : "rcx", "r11", "memory"),
					  __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														   "d"(a3) : "rcx", "r11", "memory"));
	return ret;
}

long int _syscall4(long n, long a1, long a2, long a3, long a4)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	__syscall_wrapper(__volatile__(vmgexit : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														   "d"(a3), "r"(r10) : "rcx", "r11", "memory"),
					  __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														   "d"(a3), "r"(r10) : "rcx", "r11", "memory"));
	return ret;
}

long int _syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	__syscall_wrapper(__volatile__(vmgexit : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														   "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory"),
					  __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														   "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory"));
	return ret;
}

long int _syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__syscall_wrapper(__volatile__(vmgexit : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														   "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory"),
					  __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														   "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory"));
	return ret;
}