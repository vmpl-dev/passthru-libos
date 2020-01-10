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
 * shim_syscalls.c
 *
 * This file contains macros to redirect all system calls to the system call
 * table in library OS.
 */

#include <asm/prctl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <shim_defs.h>
#include <shim_table.h>
#include <shim_syscalls.h>

long int if_call_defined(long int sys_no) {
    return shim_table[sys_no] != 0;
}

//////////////////////////////////////////////////
//  Mappings from system calls to shim calls
///////////////////////////////////////////////////

/*
  Missing, but need to be added:
  * clone
  * semctl

  from 'man unimplemented':
  NOT IMPLEMENTED in kernel (always return -ENOSYS)

  NAME
  afs_syscall,  break,  ftime,  getpmsg, gtty, lock, madvise1, mpx, prof,
  profil, putpmsg, security, stty, tuxcall, ulimit,  vserver  -
  unimplemented system calls

  SYNOPSIS
  Unimplemented system calls.

  DESCRIPTION
  These system calls are not implemented in the Linux 2.6.22 kernel.

  RETURN VALUE
  These system calls always return -1 and set errno to ENOSYS.

  NOTES
  Note  that ftime(3), profil(3) and ulimit(3) are implemented as library
  functions.

  Some system calls,  like  alloc_hugepages(2),  free_hugepages(2),  ioperm(2),
  iopl(2), and vm86(2) only exist on certain architectures.

  Some  system  calls, like ipc(2), create_module(2), init_module(2), and
  delete_module(2) only exist when the Linux kernel was built  with  support
  for them.

  SEE ALSO
  syscalls(2)

  COLOPHON
  This  page  is  part of release 3.24 of the Linux man-pages project.  A
  description of the project, and information about reporting  bugs,  can
  be found at http://www.kernel.org/doc/man-pages/.

  Linux                            2007-07-05                  UNIMPLEMENTED(2)



  Also missing from shim:
  * epoll_ctl_old
  * epoll_wait_old


  According to kernel man pages, glibc does not provide wrappers for
  every system call (append to this list as you come accross more):
  * io_setup
  * ioprio_get
  * ioprio_set
  * sysctl
  * getdents
  * tkill
  * tgkill


  Also not in libc (append to this list as you come accross more):

  * add_key: (removed in Changelog.17)
  * request_key: (removed in Changelog.17)
  * keyctl: (removed in Changelog.17)
  Although these are Linux system calls, they are not present in
  libc but can be found rather in libkeyutils. When linking,
  -lkeyutils should be specified to the linker.x

  There are probably other things of note, so put them here as you
  come across them.

*/

/* Please move implemented system call to sys/ directory and name them as the
 * most important system call */

SHIM_SYSCALL_PASSTHROUGH(read, 3, size_t, int, fd, void*, buf, size_t, count)

SHIM_SYSCALL_PASSTHROUGH(write, 3, size_t, int, fd, const void*, buf, size_t, count)

SHIM_SYSCALL_PASSTHROUGH(open, 3, int, const char*, file, int, flags, mode_t, mode)

SHIM_SYSCALL_PASSTHROUGH(close, 1, int, int, fd)

SHIM_SYSCALL_PASSTHROUGH(stat, 2, int, const char*, file, struct stat*, statbuf)

SHIM_SYSCALL_PASSTHROUGH(fstat, 2, int, int, fd, struct stat*, statbuf)

SHIM_SYSCALL_PASSTHROUGH(lstat, 2, int, const char*, file, struct stat*, statbuf)

SHIM_SYSCALL_PASSTHROUGH(poll, 3, int, struct pollfd*, fds, nfds_t, nfds, int, timeout)

SHIM_SYSCALL_PASSTHROUGH(lseek, 3, off_t, int, fd, off_t, offset, int, origin)

SHIM_SYSCALL_PASSTHROUGH(mmap, 6, void*, void*, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset)

SHIM_SYSCALL_PASSTHROUGH(mprotect, 3, int, void*, addr, size_t, len, int, prot)

SHIM_SYSCALL_PASSTHROUGH(munmap, 2, int, void*, addr, size_t, len)

SHIM_SYSCALL_PASSTHROUGH(brk, 1, void*, void*, brk)

SHIM_SYSCALL_PASSTHROUGH(rt_sigaction, 4, int, int, signum, const struct __kernel_sigaction*, act, struct __kernel_sigaction*, oldact, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(rt_sigprocmask, 3, int, int, how, const __sigset_t*, set, __sigset_t*, oldset)

SHIM_SYSCALL_PASSTHROUGH(rt_sigreturn, 1, int, int, __unused)

SHIM_SYSCALL_PASSTHROUGH(ioctl, 3, int, int, fd, int, cmd, unsigned long, arg)

SHIM_SYSCALL_PASSTHROUGH(pread64, 4, size_t, int, fd, char*, buf, size_t, count, loff_t, pos)

SHIM_SYSCALL_PASSTHROUGH(pwrite64, 4, size_t, int, fd, char*, buf, size_t, count, loff_t, pos)

SHIM_SYSCALL_PASSTHROUGH(readv, 3, ssize_t, int, fd, const struct iovec*, vec, int, vlen)

SHIM_SYSCALL_PASSTHROUGH(writev, 3, ssize_t, int, fd, const struct iovec*, vec, int, vlen)

SHIM_SYSCALL_PASSTHROUGH(access, 2, int, const char*, file, mode_t, mode)

SHIM_SYSCALL_PASSTHROUGH(pipe, 1, int, int*, fildes)

SHIM_SYSCALL_PASSTHROUGH(select, 5, int, int, nfds, fd_set*, readfds, fd_set*, writefds, fd_set*, errorfds, struct __kernel_timeval*, timeout)

SHIM_SYSCALL_PASSTHROUGH(sched_yield, 0, int)

SHIM_SYSCALL_PASSTHROUGH(mremap, 5, void*, void*, addr, size_t, old_len, size_t, new_len, int, flags, void*, new_addr)

SHIM_SYSCALL_PASSTHROUGH(msync, 3, int, void*, start, size_t, len, int, flags)

SHIM_SYSCALL_PASSTHROUGH(mincore, 3, int, void*, start, size_t, len, unsigned char*, vec)

SHIM_SYSCALL_PASSTHROUGH(madvise, 3, int, void*, start, size_t, len, int, behavior)

SHIM_SYSCALL_PASSTHROUGH(shmget, 3, int, key_t, key, size_t, size, int, shmflg)

SHIM_SYSCALL_PASSTHROUGH(shmat, 3, void*, int, shmid, const void*, shmaddr, int, shmflg)

SHIM_SYSCALL_PASSTHROUGH(shmctl, 3, int, int, shmid, int, cmd, struct shmid_ds*, buf)

SHIM_SYSCALL_PASSTHROUGH(dup, 1, int, int, fd)

SHIM_SYSCALL_PASSTHROUGH(dup2, 2, int, int, oldfd, int, newfd)

SHIM_SYSCALL_PASSTHROUGH(pause, 0, int)

SHIM_SYSCALL_PASSTHROUGH(nanosleep, 2, int, const struct __kernel_timespec*, rqtp, struct __kernel_timespec*, rmtp)

SHIM_SYSCALL_PASSTHROUGH(getitimer, 2, int, int, which, struct __kernel_itimerval*, value)

SHIM_SYSCALL_PASSTHROUGH(alarm, 1, int, unsigned int, seconds)

SHIM_SYSCALL_PASSTHROUGH(setitimer, 3, int, int, which, struct __kernel_itimerval*, value, struct __kernel_itimerval*, ovalue)

SHIM_SYSCALL_PASSTHROUGH(getpid, 0, pid_t)

SHIM_SYSCALL_PASSTHROUGH(sendfile, 4, ssize_t, int, out_fd, int, in_fd, off_t*, offset, size_t, count)

SHIM_SYSCALL_PASSTHROUGH(socket, 3, int, int, family, int, type, int, protocol)

SHIM_SYSCALL_PASSTHROUGH(connect, 3, int, int, sockfd, struct sockaddr*, addr, int, addrlen)

SHIM_SYSCALL_PASSTHROUGH(accept, 3, int, int, fd, struct sockaddr*, addr, socklen_t*, addrlen)

SHIM_SYSCALL_PASSTHROUGH(sendto, 6, ssize_t, int, fd, const void*, buf, size_t, len, int, flags, const struct sockaddr*, dest_addr, socklen_t, addrlen)

SHIM_SYSCALL_PASSTHROUGH(recvfrom, 6, ssize_t, int, fd, void*, buf, size_t, len, int, flags, struct sockaddr*, addr, socklen_t*, addrlen)

SHIM_SYSCALL_PASSTHROUGH(bind, 3, int, int, sockfd, struct sockaddr*, addr, socklen_t, addrlen)

SHIM_SYSCALL_PASSTHROUGH(listen, 2, int, int, sockfd, int, backlog)

SHIM_SYSCALL_PASSTHROUGH(sendmsg, 3, ssize_t, int, fd, struct msghdr*, msg, int, flags)

SHIM_SYSCALL_PASSTHROUGH(recvmsg, 3, ssize_t, int, fd, struct msghdr*, msg, int, flags)

SHIM_SYSCALL_PASSTHROUGH(shutdown, 2, int, int, sockfd, int, how)

SHIM_SYSCALL_PASSTHROUGH(getsockname, 3, int, int, sockfd, struct sockaddr*, addr, int*, addrlen)

SHIM_SYSCALL_PASSTHROUGH(getpeername, 3, int, int, sockfd, struct sockaddr*, addr, int*, addrlen)

SHIM_SYSCALL_PASSTHROUGH(socketpair, 4, int, int, domain, int, type, int, protocol, int*, sv)

SHIM_SYSCALL_PASSTHROUGH(setsockopt, 5, int, int, fd, int, level, int, optname, char*, optval, int, optlen)

SHIM_SYSCALL_PASSTHROUGH(getsockopt, 5, int, int, fd, int, level, int, optname, char*, optval, int*, optlen)

SHIM_SYSCALL_PASSTHROUGH(clone, 5, int, int, flags, void*, user_stack_addr, int*, parent_tidptr, int*, child_tidptr, void*, tls)

SHIM_SYSCALL_PASSTHROUGH(fork, 0, int)

SHIM_SYSCALL_PASSTHROUGH(vfork, 0, int)

SHIM_SYSCALL_PASSTHROUGH(execve, 3, int, const char*, file, const char**, argv, const char**, envp)

SHIM_SYSCALL_PASSTHROUGH(exit, 1, int, int, error_code)

SHIM_SYSCALL_PASSTHROUGH(wait4, 4, pid_t, pid_t, pid, int*, stat_addr, int, option, struct __kernel_rusage*, ru)

SHIM_SYSCALL_PASSTHROUGH(kill, 2, int, pid_t, pid, int, sig)

SHIM_SYSCALL_PASSTHROUGH(uname, 1, int, struct old_utsname*, buf)

SHIM_SYSCALL_PASSTHROUGH(semget, 3, int, key_t, key, int, nsems, int, semflg)

SHIM_SYSCALL_PASSTHROUGH(semop, 3, int, int, semid, struct sembuf*, sops, unsigned int, nsops)

SHIM_SYSCALL_PASSTHROUGH(semctl, 4, int, int, semid, int, semnum, int, cmd, unsigned long, arg)

SHIM_SYSCALL_PASSTHROUGH(shmdt, 1, int, const void*, shmaddr)

SHIM_SYSCALL_PASSTHROUGH(msgget, 2, int, key_t, key, int, msgflg)

SHIM_SYSCALL_PASSTHROUGH(msgsnd, 4, int, int, msqid, const void*, msgp, size_t, msgsz, int, msgflg)

SHIM_SYSCALL_PASSTHROUGH(msgrcv, 5, int, int, msqid, void*, msgp, size_t, msgsz, long, msgtyp, int, msgflg)

SHIM_SYSCALL_PASSTHROUGH(msgctl, 3, int, int, msqid, int, cmd, struct msqid_ds*, buf)

SHIM_SYSCALL_PASSTHROUGH(fcntl, 3, int, int, fd, int, cmd, unsigned long, arg)

SHIM_SYSCALL_PASSTHROUGH(flock, 2, int, int, fd, int, cmd)

SHIM_SYSCALL_PASSTHROUGH(fsync, 1, int, int, fd)

SHIM_SYSCALL_PASSTHROUGH(fdatasync, 1, int, int, fd)

SHIM_SYSCALL_PASSTHROUGH(truncate, 2, int, const char*, path, loff_t, length)

SHIM_SYSCALL_PASSTHROUGH(ftruncate, 2, int, int, fd, loff_t, length)

SHIM_SYSCALL_PASSTHROUGH(getdents, 3, size_t, int, fd, struct linux_dirent*, buf, size_t, count)

SHIM_SYSCALL_PASSTHROUGH(getcwd, 2, int, char*, buf, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(chdir, 1, int, const char*, filename)

SHIM_SYSCALL_PASSTHROUGH(fchdir, 1, int, int, fd)

SHIM_SYSCALL_PASSTHROUGH(rename, 2, int, const char*, oldname, const char*, newname)

SHIM_SYSCALL_PASSTHROUGH(mkdir, 2, int, const char*, pathname, int, mode)

SHIM_SYSCALL_PASSTHROUGH(rmdir, 1, int, const char*, pathname)

SHIM_SYSCALL_PASSTHROUGH(creat, 2, int, const char*, path, mode_t, mode)

SHIM_SYSCALL_PASSTHROUGH(link, 2, int, const char*, oldname, const char*, newname)

SHIM_SYSCALL_PASSTHROUGH(unlink, 1, int, const char*, file)

SHIM_SYSCALL_PASSTHROUGH(symlink, 2, int, const char*, old, const char*, new)

SHIM_SYSCALL_PASSTHROUGH(readlink, 3, int, const char*, path, char*, buf, size_t, bufsize)

SHIM_SYSCALL_PASSTHROUGH(chmod, 2, int, const char*, filename, mode_t, mode)

SHIM_SYSCALL_PASSTHROUGH(fchmod, 2, int, int, fd, mode_t, mode)

SHIM_SYSCALL_PASSTHROUGH(chown, 3, int, const char*, filename, uid_t, user, gid_t, group)

SHIM_SYSCALL_PASSTHROUGH(fchown, 3, int, int, fd, uid_t, user, gid_t, group)

SHIM_SYSCALL_PASSTHROUGH(lchown, 3, int, const char*, filename, uid_t, user, gid_t, group)

SHIM_SYSCALL_PASSTHROUGH(umask, 1, mode_t, mode_t, mask)

SHIM_SYSCALL_PASSTHROUGH(gettimeofday, 2, int, struct __kernel_timeval*, tv, struct __kernel_timezone*, tz)

SHIM_SYSCALL_PASSTHROUGH(getrlimit, 2, int, int, resource, struct __kernel_rlimit*, rlim)

SHIM_SYSCALL_PASSTHROUGH(getrusage, 2, int, int, who, struct __kernel_rusage*, ru)

SHIM_SYSCALL_PASSTHROUGH(sysinfo, 1, int, struct sysinfo*, info)

SHIM_SYSCALL_PASSTHROUGH(times, 1, int, struct tms*, tbuf)

SHIM_SYSCALL_PASSTHROUGH(ptrace, 4, int, long, request, pid_t, pid, void*, addr, void*, data)

SHIM_SYSCALL_PASSTHROUGH(getuid, 0, uid_t)

SHIM_SYSCALL_PASSTHROUGH(syslog, 3, int, int, type, char*, buf, int, len)

SHIM_SYSCALL_PASSTHROUGH(getgid, 0, gid_t)

SHIM_SYSCALL_PASSTHROUGH(setuid, 1, int, uid_t, uid)

SHIM_SYSCALL_PASSTHROUGH(setgid, 1, int, gid_t, gid)

SHIM_SYSCALL_PASSTHROUGH(setgroups, 2, int, int, gidsetsize, gid_t*, grouplist)

SHIM_SYSCALL_PASSTHROUGH(getgroups, 2, int, int, gidsetsize, gid_t*, grouplist)

SHIM_SYSCALL_PASSTHROUGH(geteuid, 0, uid_t)

SHIM_SYSCALL_PASSTHROUGH(getegid, 0, gid_t)

SHIM_SYSCALL_PASSTHROUGH(setpgid, 2, int, pid_t, pid, pid_t, pgid)

SHIM_SYSCALL_PASSTHROUGH(getppid, 0, pid_t)

SHIM_SYSCALL_PASSTHROUGH(getpgrp, 0, pid_t)

SHIM_SYSCALL_PASSTHROUGH(setsid, 0, int)

SHIM_SYSCALL_PASSTHROUGH(setreuid, 2, int, uid_t, ruid, uid_t, euid)

SHIM_SYSCALL_PASSTHROUGH(setregid, 2, int, gid_t, rgid, gid_t, egid)

SHIM_SYSCALL_PASSTHROUGH(setresuid, 3, int, uid_t, ruid, uid_t, euid, uid_t, suid)

SHIM_SYSCALL_PASSTHROUGH(getresuid, 3, int, uid_t*, ruid, uid_t*, euid, uid_t*, suid)

SHIM_SYSCALL_PASSTHROUGH(setresgid, 3, int, gid_t, rgid, gid_t, egid, gid_t, sgid)

SHIM_SYSCALL_PASSTHROUGH(getresgid, 3, int, gid_t*, rgid, gid_t*, egid, gid_t*, sgid)

SHIM_SYSCALL_PASSTHROUGH(getpgid, 1, int, pid_t, pid)

SHIM_SYSCALL_PASSTHROUGH(setfsuid, 1, int, uid_t, uid)

SHIM_SYSCALL_PASSTHROUGH(setfsgid, 1, int, gid_t, gid)

SHIM_SYSCALL_PASSTHROUGH(getsid, 1, int, pid_t, pid)

SHIM_SYSCALL_PASSTHROUGH(capget, 2, int, cap_user_header_t, header, cap_user_data_t, dataptr)

SHIM_SYSCALL_PASSTHROUGH(capset, 2, int, cap_user_header_t, header, const cap_user_data_t, data)

SHIM_SYSCALL_PASSTHROUGH(rt_sigpending, 2, int, __sigset_t*, set, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(rt_sigtimedwait, 4, int, const __sigset_t*, uthese, siginfo_t*, uinfo, const struct timespec*, uts, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(rt_sigqueueinfo, 3, int, int, pid, int, sig, siginfo_t*, uinfo)

SHIM_SYSCALL_PASSTHROUGH(rt_sigsuspend, 1, int, const __sigset_t*, mask)

SHIM_SYSCALL_PASSTHROUGH(sigaltstack, 2, int, const stack_t*, ss, stack_t*, oss)

SHIM_SYSCALL_PASSTHROUGH(utime, 2, int, char*, filename, struct utimbuf*, times)

SHIM_SYSCALL_PASSTHROUGH(mknod, 3, int, const char*, filename, int, mode, unsigned, dev)

SHIM_SYSCALL_PASSTHROUGH(uselib, 1, int, const char*, library)

SHIM_SYSCALL_PASSTHROUGH(personality, 1, int, unsigned int, personality)

SHIM_SYSCALL_PASSTHROUGH(ustat, 2, int, unsigned, dev, struct __kernel_ustat*, ubuf)

SHIM_SYSCALL_PASSTHROUGH(statfs, 2, int, const char*, path, struct statfs*, buf)

SHIM_SYSCALL_PASSTHROUGH(fstatfs, 2, int, int, fd, struct statfs*, buf)

SHIM_SYSCALL_PASSTHROUGH(sysfs, 3, int, int, option, unsigned long, arg1, unsigned long, arg2)

SHIM_SYSCALL_PASSTHROUGH(getpriority, 2, int, int, which, int, who)

SHIM_SYSCALL_PASSTHROUGH(setpriority, 3, int, int, which, int, who, int, niceval)

SHIM_SYSCALL_PASSTHROUGH(sched_setparam, 2, int, pid_t, pid, struct __kernel_sched_param*, param)

SHIM_SYSCALL_PASSTHROUGH(sched_getparam, 2, int, pid_t, pid, struct __kernel_sched_param*, param)

SHIM_SYSCALL_PASSTHROUGH(sched_setscheduler, 3, int, pid_t, pid, int, policy, struct __kernel_sched_param*, param)

SHIM_SYSCALL_PASSTHROUGH(sched_getscheduler, 1, int, pid_t, pid)

SHIM_SYSCALL_PASSTHROUGH(sched_get_priority_max, 1, int, int, policy)

SHIM_SYSCALL_PASSTHROUGH(sched_get_priority_min, 1, int, int, policy)

SHIM_SYSCALL_PASSTHROUGH(sched_rr_get_interval, 2, int, pid_t, pid, struct timespec*, interval)

SHIM_SYSCALL_PASSTHROUGH(mlock, 2, int, void*, start, size_t, len)

SHIM_SYSCALL_PASSTHROUGH(munlock, 2, int, void*, start, size_t, len)

SHIM_SYSCALL_PASSTHROUGH(mlockall, 1, int, int, flags)

SHIM_SYSCALL_PASSTHROUGH(munlockall, 0, int)

SHIM_SYSCALL_PASSTHROUGH(vhangup, 0, int)

SHIM_SYSCALL_PASSTHROUGH(modify_ldt, 3, int, int, func, void*, ptr, unsigned long, bytecount)

SHIM_SYSCALL_PASSTHROUGH(pivot_root, 2, int, const char*, new_root, const char*, put_old)

SHIM_SYSCALL_PASSTHROUGH(_sysctl, 1, int, struct __kernel_sysctl_args*, args)

SHIM_SYSCALL_PASSTHROUGH(prctl, 5, int, int, option, unsigned long, arg2, unsigned long, arg3, unsigned long, arg4, unsigned long, arg5)

SHIM_SYSCALL_PASSTHROUGH(arch_prctl, 2, void*, int, code, void*, addr)

SHIM_SYSCALL_PASSTHROUGH(adjtimex, 1, int, struct ____kernel_timex*, txc_p)

SHIM_SYSCALL_PASSTHROUGH(setrlimit, 2, int, int, resource, struct __kernel_rlimit*, rlim)

SHIM_SYSCALL_PASSTHROUGH(chroot, 1, int, const char*, filename)

SHIM_SYSCALL_PASSTHROUGH(sync, 0, int)

SHIM_SYSCALL_PASSTHROUGH(acct, 1, int, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(settimeofday, 2, int, struct timeval*, tv, struct __kernel_timezone*, tz)

SHIM_SYSCALL_PASSTHROUGH(mount, 5, int, char*, dev_name, char*, dir_name, char*, type, unsigned long, flags, void*, data)

SHIM_SYSCALL_PASSTHROUGH(umount2, 2, int, const char*, target, int, flags)

SHIM_SYSCALL_PASSTHROUGH(swapon, 2, int, const char*, specialfile, int, swap_flags)

SHIM_SYSCALL_PASSTHROUGH(swapoff, 1, int, const char*, specialfile)

SHIM_SYSCALL_PASSTHROUGH(reboot, 4, int, int, magic1, int, magic2, int, cmd, void*, arg)

SHIM_SYSCALL_PASSTHROUGH(sethostname, 2, int, char*, name, int, len)

SHIM_SYSCALL_PASSTHROUGH(setdomainname, 2, int, char*, name, int, len)

SHIM_SYSCALL_PASSTHROUGH(iopl, 1, int, int, level)

SHIM_SYSCALL_PASSTHROUGH(ioperm, 3, int, unsigned long, from, unsigned long, num, int, on)

SHIM_SYSCALL_PASSTHROUGH(create_module, 2, int, const char*, name, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(init_module, 3, int, void*, umod, unsigned long, len, const char*, uargs)

SHIM_SYSCALL_PASSTHROUGH(delete_module, 2, int, const char*, name_user, unsigned int, flags)

SHIM_SYSCALL_PASSTHROUGH(query_module, 5, int, const char*, name, int, which, void*, buf, size_t, bufsize, size_t*, retsize)

SHIM_SYSCALL_PASSTHROUGH(quotactl, 4, int, int, cmd, const char*, special, qid_t, id, void*, addr)

SHIM_SYSCALL_PASSTHROUGH(gettid, 0, pid_t)

SHIM_SYSCALL_PASSTHROUGH(readahead, 3, int, int, fd, loff_t, offset, size_t, count)

SHIM_SYSCALL_PASSTHROUGH(setxattr, 5, int, const char*, path, const char*, name, const void*, value, size_t, size, int, flags)

SHIM_SYSCALL_PASSTHROUGH(lsetxattr, 5, int, const char*, path, const char*, name, const void*, value, size_t, size, int, flags)

SHIM_SYSCALL_PASSTHROUGH(fsetxattr, 5, int, int, fd, const char*, name, const void*, value, size_t, size, int, flags)

SHIM_SYSCALL_PASSTHROUGH(getxattr, 4, int, const char*, path, const char*, name, void*, value, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(lgetxattr, 4, int, const char*, path, const char*, name, void*, value, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(fgetxattr, 4, int, int, fd, const char*, name, void*, value, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(listxattr, 3, int, const char*, path, char*, list, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(llistxattr, 3, int, const char*, path, char*, list, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(flistxattr, 3, int, int, fd, char*, list, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(removexattr, 2, int, const char*, path, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(lremovexattr, 2, int, const char*, path, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(fremovexattr, 2, int, int, fd, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(tkill, 2, int, pid_t, pid, int, sig)

SHIM_SYSCALL_PASSTHROUGH(time, 1, time_t, time_t*, tloc)

SHIM_SYSCALL_PASSTHROUGH(futex, 6, int, int*, uaddr, int, op, int, val, void*, utime, int*, uaddr2, int, val3)

SHIM_SYSCALL_PASSTHROUGH(sched_setaffinity, 3, int, pid_t, pid, size_t, len, __kernel_cpu_set_t*, user_mask_ptr)

SHIM_SYSCALL_PASSTHROUGH(sched_getaffinity, 3, int, pid_t, pid, size_t, len, __kernel_cpu_set_t*, user_mask_ptr)

SHIM_SYSCALL_PASSTHROUGH(set_thread_area, 1, int, struct user_desc*, u_info)

SHIM_SYSCALL_PASSTHROUGH(io_setup, 2, int, unsigned, nr_reqs, aio_context_t*, ctx)

SHIM_SYSCALL_PASSTHROUGH(io_destroy, 1, int, aio_context_t, ctx)

SHIM_SYSCALL_PASSTHROUGH(io_getevents, 5, int, aio_context_t, ctx_id, long, min_nr, long, nr, struct io_event*, events, struct timespec*, timeout)

SHIM_SYSCALL_PASSTHROUGH(io_submit, 3, int, aio_context_t, ctx_id, long, nr, struct iocb**, iocbpp)

SHIM_SYSCALL_PASSTHROUGH(io_cancel, 3, int, aio_context_t, ctx_id, struct iocb*, iocb, struct io_event*, result)

SHIM_SYSCALL_PASSTHROUGH(get_thread_area, 1, int, struct user_desc*, u_info)

SHIM_SYSCALL_PASSTHROUGH(lookup_dcookie, 3, int, unsigned long, cookie64, char*, buf, size_t, len)

SHIM_SYSCALL_PASSTHROUGH(epoll_create, 1, int, int, size)

SHIM_SYSCALL_PASSTHROUGH(remap_file_pages, 5, int, void*, start, size_t, size, int, prot, ssize_t, pgoff, int, flags)

SHIM_SYSCALL_PASSTHROUGH(getdents64, 3, size_t, int, fd, struct linux_dirent64*, buf, size_t, count)

SHIM_SYSCALL_PASSTHROUGH(set_tid_address, 1, int, int*, tidptr)

SHIM_SYSCALL_PASSTHROUGH(restart_syscall, 0, int)

SHIM_SYSCALL_PASSTHROUGH(semtimedop, 4, int, int, semid, struct sembuf*, sops, unsigned int, nsops, const struct timespec*, timeout)

SHIM_SYSCALL_PASSTHROUGH(fadvise64, 4, int, int, fd, loff_t, offset, size_t, len, int, advice)

SHIM_SYSCALL_PASSTHROUGH(timer_create, 3, int, clockid_t, which_clock, struct sigevent*, timer_event_spec, timer_t*, created_timer_id)

SHIM_SYSCALL_PASSTHROUGH(timer_settime, 4, int, timer_t, timer_id, int, flags, const struct __kernel_itimerspec*, new_setting, struct __kernel_itimerspec*, old_setting)

SHIM_SYSCALL_PASSTHROUGH(timer_gettime, 2, int, timer_t, timer_id, struct __kernel_itimerspec*, setting)

SHIM_SYSCALL_PASSTHROUGH(timer_getoverrun, 1, int, timer_t, timer_id)

SHIM_SYSCALL_PASSTHROUGH(timer_delete, 1, int, timer_t, timer_id)

SHIM_SYSCALL_PASSTHROUGH(clock_settime, 2, int, clockid_t, which_clock, const struct timespec*, tp)

SHIM_SYSCALL_PASSTHROUGH(clock_gettime, 2, int, clockid_t, which_clock, struct timespec*, tp)

SHIM_SYSCALL_PASSTHROUGH(clock_getres, 2, int, clockid_t, which_clock, struct timespec*, tp)

SHIM_SYSCALL_PASSTHROUGH(clock_nanosleep, 4, int, clockid_t, which_clock, int, flags, const struct timespec*, rqtp, struct timespec*, rmtp)

SHIM_SYSCALL_PASSTHROUGH(exit_group, 1, int, int, error_code)

SHIM_SYSCALL_PASSTHROUGH(epoll_wait, 4, int, int, epfd, struct __kernel_epoll_event*, events, int, maxevents, int, timeout_ms)

SHIM_SYSCALL_PASSTHROUGH(epoll_ctl, 4, int, int, epfd, int, op, int, fd, struct __kernel_epoll_event*, event)

SHIM_SYSCALL_PASSTHROUGH(tgkill, 3, int, pid_t, tgid, pid_t, pid, int, sig)

SHIM_SYSCALL_PASSTHROUGH(utimes, 2, int, char*, filename, struct timeval*, utimes)

SHIM_SYSCALL_PASSTHROUGH(mbind, 6, int, void*, start, unsigned long, len, int, mode, unsigned long*, nmask, unsigned long, maxnode, int, flags)

SHIM_SYSCALL_PASSTHROUGH(set_mempolicy, 3, int, int, mode, unsigned long*, nmask, unsigned long, maxnode)

SHIM_SYSCALL_PASSTHROUGH(get_mempolicy, 5, int, int*, policy, unsigned long*, nmask, unsigned long, maxnode, unsigned long, addr, unsigned long, flags)

SHIM_SYSCALL_PASSTHROUGH(mq_open, 4, int, const char*, name, int, oflag, mode_t, mode, struct __kernel_mq_attr*, attr)

SHIM_SYSCALL_PASSTHROUGH(mq_unlink, 1, int, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(mq_timedsend, 5, int, __kernel_mqd_t, mqdes, const char*, msg_ptr, size_t, msg_len, unsigned int, msg_prio, const struct timespec*, abs_timeout)

SHIM_SYSCALL_PASSTHROUGH(mq_timedreceive, 5, int, __kernel_mqd_t, mqdes, char*, msg_ptr, size_t, msg_len, unsigned int*, msg_prio, const struct timespec*, abs_timeout)

SHIM_SYSCALL_PASSTHROUGH(mq_notify, 2, int, __kernel_mqd_t, mqdes, const struct sigevent*, notification)

SHIM_SYSCALL_PASSTHROUGH(mq_getsetattr, 3, int, __kernel_mqd_t, mqdes, const struct __kernel_mq_attr*, mqstat, struct __kernel_mq_attr*, omqstat)

SHIM_SYSCALL_PASSTHROUGH(waitid, 5, int, int, which, pid_t, pid, siginfo_t*, infop, int, options, struct __kernel_rusage*, ru)

SHIM_SYSCALL_PASSTHROUGH(ioprio_set, 3, int, int, which, int, who, int, ioprio)

SHIM_SYSCALL_PASSTHROUGH(ioprio_get, 2, int, int, which, int, who)

SHIM_SYSCALL_PASSTHROUGH(inotify_init, 0, int)

SHIM_SYSCALL_PASSTHROUGH(inotify_add_watch, 3, int, int, fd, const char*, path, unsigned int, mask)

SHIM_SYSCALL_PASSTHROUGH(inotify_rm_watch, 2, int, int, fd, unsigned int, wd)

SHIM_SYSCALL_PASSTHROUGH(migrate_pages, 4, int, pid_t, pid, unsigned long, maxnode, const unsigned long*, from, const unsigned long*, to)

SHIM_SYSCALL_PASSTHROUGH(openat, 4, int, int, dfd, const char*, filename, int, flags, int, mode)

SHIM_SYSCALL_PASSTHROUGH(mkdirat, 3, int, int, dfd, const char*, pathname, int, mode)

SHIM_SYSCALL_PASSTHROUGH(mknodat, 4, int, int, dfd, const char*, filename, int, mode, unsigned, dev)

SHIM_SYSCALL_PASSTHROUGH(fchownat, 5, int, int, dfd, const char*, filename, uid_t, user, gid_t, group, int, flag)

SHIM_SYSCALL_PASSTHROUGH(futimesat, 3, int, int, dfd, const char*, filename, struct timeval*, utimes)

SHIM_SYSCALL_PASSTHROUGH(newfstatat, 4, int, int, dfd, const char*, filename, struct stat*, statbuf, int, flag)

SHIM_SYSCALL_PASSTHROUGH(unlinkat, 3, int, int, dfd, const char*, pathname, int, flag)

SHIM_SYSCALL_PASSTHROUGH(renameat, 4, int, int, olddfd, const char*, oldname, int, newdfd, const char*, newname)

SHIM_SYSCALL_PASSTHROUGH(linkat, 5, int, int, olddfd, const char*, oldname, int, newdfd, const char*, newname, int, flags)

SHIM_SYSCALL_PASSTHROUGH(symlinkat, 3, int, const char*, oldname, int, newdfd, const char*, newname)

SHIM_SYSCALL_PASSTHROUGH(readlinkat, 4, int, int, dfd, const char*, path, char*, buf, int, bufsiz)

SHIM_SYSCALL_PASSTHROUGH(fchmodat, 3, int, int, dfd, const char*, filename, mode_t, mode)

SHIM_SYSCALL_PASSTHROUGH(faccessat, 3, int, int, dfd, const char*, filename, int, mode)

SHIM_SYSCALL_PASSTHROUGH(pselect6, 6, int, int, nfds, fd_set*, readfds, fd_set*, writefds, fd_set*, errorfds, const struct __kernel_timespec*, tsp, const __sigset_t*, sigmask)

SHIM_SYSCALL_PASSTHROUGH(ppoll, 5, int, struct pollfd*, fds, int, nfds, struct timespec*, tsp, const __sigset_t*, sigmask, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(unshare, 1, int, int, unshare_flags)

SHIM_SYSCALL_PASSTHROUGH(set_robust_list, 2, int, struct robust_list_head*, head, size_t, len)

SHIM_SYSCALL_PASSTHROUGH(get_robust_list, 3, int, pid_t, pid, struct robust_list_head**, head, size_t*, len)

SHIM_SYSCALL_PASSTHROUGH(splice, 6, int, int, fd_in, loff_t*, off_in, int, fd_out, loff_t*, off_out, size_t, len, int, flags)

SHIM_SYSCALL_PASSTHROUGH(tee, 4, int, int, fdin, int, fdout, size_t, len, unsigned int, flags)

SHIM_SYSCALL_PASSTHROUGH(sync_file_range, 4, int, int, fd, loff_t, offset, loff_t, nbytes, int, flags)

SHIM_SYSCALL_PASSTHROUGH(vmsplice, 4, int, int, fd, const struct iovec*, iov, unsigned long, nr_segs, int, flags)

SHIM_SYSCALL_PASSTHROUGH(move_pages, 6, int, pid_t, pid, unsigned long, nr_pages, void**, pages, const int*, nodes, int*, status, int, flags)

SHIM_SYSCALL_PASSTHROUGH(utimensat, 4, int, int, dfd, const char*, filename, struct timespec*, utimes, int, flags)

SHIM_SYSCALL_PASSTHROUGH(epoll_pwait, 6, int, int, epfd, struct __kernel_epoll_event*, events, int, maxevents, int, timeout_ms, const __sigset_t*, sigmask, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(signalfd, 3, int, int, ufd, __sigset_t*, user_mask, size_t, sizemask)

SHIM_SYSCALL_PASSTHROUGH(timerfd_create, 2, int, int, clockid, int, flags)

SHIM_SYSCALL_PASSTHROUGH(eventfd, 1, int, int, count)

SHIM_SYSCALL_PASSTHROUGH(fallocate, 4, int, int, fd, int, mode, loff_t, offset, loff_t, len)

SHIM_SYSCALL_PASSTHROUGH(timerfd_settime, 4, int, int, ufd, int, flags, const struct __kernel_itimerspec*, utmr, struct __kernel_itimerspec*, otmr)

SHIM_SYSCALL_PASSTHROUGH(timerfd_gettime, 2, int, int, ufd, struct __kernel_itimerspec*, otmr)

SHIM_SYSCALL_PASSTHROUGH(accept4, 4, int, int, sockfd, struct sockaddr*, addr, socklen_t*, addrlen, int, flags)

SHIM_SYSCALL_PASSTHROUGH(signalfd4, 4, int, int, ufd, __sigset_t*, user_mask, size_t, sizemask, int, flags)

SHIM_SYSCALL_PASSTHROUGH(eventfd2, 2, int, int, count, int, flags)

SHIM_SYSCALL_PASSTHROUGH(epoll_create1, 1, int, int, flags)

SHIM_SYSCALL_PASSTHROUGH(dup3, 3, int, int, oldfd, int, newfd, int, flags)

SHIM_SYSCALL_PASSTHROUGH(pipe2, 2, int, int*, fildes, int, flags)

SHIM_SYSCALL_PASSTHROUGH(inotify_init1, 1, int, int, flags)

SHIM_SYSCALL_PASSTHROUGH(preadv, 5, int, unsigned long, fd, const struct iovec*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)

SHIM_SYSCALL_PASSTHROUGH(pwritev, 5, int, unsigned long, fd, const struct iovec*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)

SHIM_SYSCALL_PASSTHROUGH(rt_tgsigqueueinfo, 4, int, pid_t, tgid, pid_t, pid, int, sig, siginfo_t*, uinfo)

SHIM_SYSCALL_PASSTHROUGH(perf_event_open, 5, int, struct perf_event_attr*, attr_uptr, pid_t, pid, int, cpu, int, group_fd, int, flags)

SHIM_SYSCALL_PASSTHROUGH(recvmmsg, 5, ssize_t, int, fd, struct mmsghdr*, msg, size_t, vlen, int, flags, struct __kernel_timespec*, timeout)

SHIM_SYSCALL_PASSTHROUGH(fanotify_init, 2, int, int, flags, int, event_f_flags)

SHIM_SYSCALL_PASSTHROUGH(fanotify_mark, 5, int, int, fanotify_fd, int, flags, unsigned long, mask, int, fd, const char*, pathname)

SHIM_SYSCALL_PASSTHROUGH(prlimit64, 4, int, pid_t, pid, int, resource, const struct __kernel_rlimit64*, new_rlim, struct __kernel_rlimit64*, old_rlim)

SHIM_SYSCALL_PASSTHROUGH(name_to_handle_at, 5, int, int, dfd, const char*, name, struct linux_file_handle*, handle, int*, mnt_id, int, flag)

SHIM_SYSCALL_PASSTHROUGH(open_by_handle_at, 3, int, int, mountdirfd, struct linux_file_handle*, handle, int, flags)

SHIM_SYSCALL_PASSTHROUGH(clock_adjtime, 2, int, clockid_t, which_clock, struct timex*, tx)

SHIM_SYSCALL_PASSTHROUGH(syncfs, 1, int, int, fd)

SHIM_SYSCALL_PASSTHROUGH(sendmmsg, 4, ssize_t, int, fd, struct mmsghdr*, msg, size_t, vlen, int, flags)

SHIM_SYSCALL_PASSTHROUGH(setns, 2, int, int, fd, int, nstype)

SHIM_SYSCALL_PASSTHROUGH(getcpu, 3, int, unsigned*, cpu, unsigned*, node, struct getcpu_cache*, cache)
