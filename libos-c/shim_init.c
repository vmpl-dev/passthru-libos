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

#include <asm/mman.h>
#include <asm/ioctls.h>
#include <asm/errno.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

/* At the begining of entry point, rsp starts at argc, then argvs,
   envps and auxvs. Here we store rsp to rdi, so it will not be
   messed up by function calls */
__asm__ (".global shim_start \n"
     "  .type shim_start,@function \n"
     "shim_start: \n"
     "  movq %rsp, %rdi \n"
     "  call shim_linux_main \n");

#define RTLD_BOOTSTRAP

/* shim_start is the entry point of libsyscall.so */
#define _ENTRY shim_start

static int pagesz = PRESET_PAGESIZE;
static int uid, gid;
#if USE_VDSO_GETTIME == 1
static ElfW(Addr) sysinfo_ehdr;
#endif

static void shim_init_bootstrap(void * args, const char ** loader_name,
                                int * pargc, const char *** pargv, const char *** penvp)
{
    /*
     * fetch arguments and environment variables, the previous stack
     * pointer is in rdi (arg). The stack structure starting at rdi
     * will look like:
     *            auxv[m - 1] = AT_NULL
     *            ...
     *            auxv[0]
     *            envp[n - 1] = NULL
     *            ...
     *            envp[0]
     *            argv[argc] = NULL
     *            argv[argc - 1]
     *            ...
     *            argv[0]
     *            argc
     *       ---------------------------------------
     *            user stack
     */
    const char ** all_args = (const char **) args;
    int argc = (uintptr_t) all_args[0];
    const char ** argv = &all_args[1];
    const char ** envp = argv + argc + 1;

    /* fetch environment information from aux vectors */
    const char ** e = envp;
    for (; *e ; e++)
        ;

    ElfW(auxv_t) *av;
    for (av = (ElfW(auxv_t) *) (e + 1) ; av->a_type != AT_NULL ; av++)
        switch (av->a_type) {
            case AT_PAGESZ:
                pagesz = av->a_un.a_val;
                break;
            case AT_UID:
            case AT_EUID:
                uid ^= av->a_un.a_val;
                break;
            case AT_GID:
            case AT_EGID:
                gid ^= av->a_un.a_val;
                break;
        }

    *loader_name = argv[0];
    argv++;
    argc--;
    *pargc = argc;
    *pargv = argv;
    *penvp = envp;
}

#include "dynamic_link.h"

static struct link_map shim_map;

#ifdef __x86_64__
# include "elf-x86_64.h"
#else
# error "unsupported architecture"
#endif

void shim_linux_main (void * args)
{
    const char * loader_name = NULL;
    const char ** argv, ** envp;
    int argc;
    /* parse argc, argv, envp and auxv */
    shim_init_bootstrap(args, &pal_name, &argc, &argv, &envp);

    shim_map.l_addr = elf_machine_load_address();
    shim_map.l_name = loader_name;
    elf_get_dynamic_info((void *) shim_map.l_addr + elf_machine_dynamic(),
                         shim_map.l_info, shim_map.l_addr);
    ELF_DYNAMIC_RELOCATE(&shim_map);

    int fd = INLINE_SYSCALL(open, 3, argv[0], O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(fd)) {
        // DEP 10/20/16: Don't silently swallow permission errors
        // accessing the manifest
        if (fd == -13) {
            printf("Warning: Attempt to open file %s failed with permission denied\n", argv[0]);
        }
        goto done_init;
    }

    if (!check_elf_object(fd)) {
        exec = fd;
        goto done_init;
    }


done_init:
    if (!parent && !exec && !manifest) {
        printf("Executable not found\n");
        printf("USAGE: %s [executable|manifest] args ...\n", pal_name);
    }

}
