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
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

/*
* shim_rtld.c
*
* This file contains codes for dynamic loading of ELF binaries in library OS.
* It's espeically used for loading interpreter (ld.so, in general) and
* optimization of execve.
* Most of the source codes are imported from GNU C library.
*/

#include <api.h>
#include <shim_defs.h>
#include <shim_passthru.h>
#include <errno.h>
#include <elf.h>
#include <asm/prctl.h>
#include <asm/mman.h>
#include <linux/fcntl.h>

void* __load_address;
void* __load_address_end;

/*
* This structure is similar to glibc's link_map, but only contains
* basic information needed for loading ELF binaries into memory
* without relocation.
*/
struct link_map {
    void* base_addr;
    void* dynamic;
    void* map_start;
    void* map_end;
    void* entry;
    const char* interp_name;
    void* phdr_addr;
    size_t phdr_num;
};

static struct link_map exec_map, interp_map;

#if __WORDSIZE == 32
# define FILEBUF_SIZE 512
#else
# define FILEBUF_SIZE 832
#endif

static int load_link_map(struct link_map* map, int file) {
    int ret;

    char filebuf[FILEBUF_SIZE];
    ret = INLINE_SYSCALL(pread64, 4, file, filebuf, FILEBUF_SIZE, 0);
    if (IS_ERR(ret))
        return ERRNO(ret);

    const Elf64_Ehdr* ehdr = (void*)filebuf;
    const Elf64_Phdr* phdr = (void*)filebuf + ehdr->e_phoff;
    const Elf64_Phdr* ph;
    uintptr_t mapstart = (uintptr_t)-1;
    uintptr_t mapend   = (uintptr_t)0;

    memset(map, 0, sizeof(*map));

    for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++)
        switch (ph->p_type) {
            case PT_DYNAMIC:
                map->dynamic = (void*)ph->p_vaddr;
                break;
            case PT_INTERP:
                map->interp_name = (const char*)ph->p_vaddr;
            case PT_LOAD: {
                uintptr_t start = ALIGN_DOWN(ph->p_vaddr);
                uintptr_t end   = ALIGN_UP(ph->p_vaddr + ph->p_memsz);
                if (start < mapstart)
                    mapstart = start;
                if (end > mapend)
                    mapend = end;
                break;
            }
        }

    if (mapstart >= mapend)
        return -EINVAL;

    uintptr_t mapoff = 0;

    if (ehdr->e_type == ET_DYN) {
        uintptr_t mapaddr = INLINE_SYSCALL(mmap, 6, NULL, mapend - mapstart,
                                           PROT_NONE, MAP_PRIVATE|MAP_FILE, file, 0);
        if (IS_ERR_P(mapaddr))
            return -ERRNO_P(mapaddr);

        mapoff = mapaddr - mapstart;
    } else {
        uintptr_t mapaddr = INLINE_SYSCALL(mmap, 6, mapstart, mapend - mapstart,
                                           PROT_NONE, MAP_FIXED|MAP_PRIVATE|MAP_FILE,
                                           file, 0);
        if (IS_ERR_P(mapaddr))
            return -ERRNO_P(mapaddr);
    }

    for (ph = phdr ; ph < &phdr[ehdr->e_phnum] ; ph++) {
        if (ph->p_type != PT_LOAD)
            continue;

        void* start = (void*)ALIGN_DOWN(ph->p_vaddr);
        void* end = (void*)ph->p_vaddr + ph->p_memsz;
        void* file_end = (void*)ph->p_vaddr + ph->p_filesz;
        void* file_end_aligned = (void*)ALIGN_UP(file_end);
        off_t file_off = ALIGN_DOWN(ph->p_offset);
        void* mapaddr = (void*)(mapoff + start);

        int prot = 0;
        if (ph->p_flags & PF_R)
            prot |= PROT_READ;
        if (ph->p_flags & PF_W)
            prot |= PROT_WRITE;
        if (ph->p_flags & PF_X)
            prot |= PROT_EXEC;

        mapaddr = (void*)INLINE_SYSCALL(mmap, 6, mapaddr,
                                        file_end_aligned - start, prot,
                                        MAP_PRIVATE|MAP_FILE|MAP_FIXED,
                                        file, file_off);
        if (IS_ERR_P(mapaddr))
            return -ERRNO_P(mapaddr);

        if (end > file_end) {
            /*
             * If there are remaining bytes at the last page, simply zero
             * the bytes.
             */
            if (file_end < file_end_aligned) {
                memset((void*)(mapoff + file_end), 0, file_end_aligned - file_end);
                file_end = file_end_aligned;
            }

            /* Allocate free pages for the rest of the section*/
            if (file_end < end) {
                end = (void*)ALIGN_UP(end);
                assert(ALIGNED(file_end));
                mapaddr = (void*)(mapoff + file_end);
                INLINE_SYSCALL(mmap, 6, mapaddr, end - file_end,
                               prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            }
        }
    }

    map->base_addr = (void*)mapoff;
    map->dynamic   = (void*)mapoff + (uintptr_t) map->dynamic;
    map->map_start = (void*)mapoff + mapstart;
    map->map_end   = (void*)mapoff + mapend;
    map->entry     = (void*)mapoff + (uintptr_t) ehdr->e_entry;
    map->phdr_addr = map->map_start + ehdr->e_phoff;
    map->phdr_num  = ehdr->e_phnum;

    return 0;
}

static int load_link_map_by_path(struct link_map* map, const char* dir_path,
                                 const char* path) {
    int dirfd = AT_FDCWD;
    if (dir_path) {
        dirfd = INLINE_SYSCALL(open, 3, dir_path, O_DIRECTORY, 0);
        if (IS_ERR(dirfd))
            return -ERRNO(dirfd);
    }

    int fd = INLINE_SYSCALL(openat, 4, dirfd, path, O_RDONLY, 0);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    int ret = load_link_map(map, fd);
    INLINE_SYSCALL(close, 1, fd);
    return ret;
}

int init_loader(const char* exec_path, const char* libc_location) {
    int ret = load_link_map_by_path(&exec_map, NULL, exec_path);
    if (ret < 0)
        return ret;

    if (exec_map.interp_name) {
        const char* interp_name = exec_map.interp_name;
        const char* filename = interp_name + strlen(interp_name) - 1;
        while (filename > interp_name &&*filename != '/')
            filename--;
        if (*filename == '/')
            filename++;

        /* Try loading the interpreter */
        ret = load_link_map_by_path(&interp_map, libc_location, filename);
        if (ret < 0)
            return ret;
    }

    return 0;
}

int start_execute(int argc, const char** argp, elf_auxv_t* auxp) {
    elf_auxv_t* av;
    for (av = auxp; av->a_type != AT_NULL; av++)
        switch (av->a_type) {
            case AT_PHDR:
                av->a_un.a_val = (__typeof(auxp[0].a_un.a_val))exec_map.phdr_addr;
                break;
            case AT_PHNUM:
                av->a_un.a_val = exec_map.phdr_num;
                break;
            case AT_ENTRY:
                av->a_un.a_val = (uintptr_t)exec_map.entry;
                break;
            case AT_BASE:
                av->a_un.a_val = (uintptr_t)interp_map.base_addr;
                break;
        }

#if defined(__x86_64__)
    __asm__ __volatile__ ("movq %%rbx, %%rsp\r\n"
                          "pushq %%rdi\r\n"
                          "jmp *%%rax\r\n"

                          :
                          : "a"(interp_map.entry), "b"(argp), "D"(argc)

                          : "memory");
#else
# error "architecture not supported"
#endif

    /* Should not reach here */
    INLINE_SYSCALL(exit, 1, -1);
    return 0;
}

/* At the begining of entry point, rsp starts at argc, then argvs,
   envps and auxvs. Here we store rsp to rdi, so it will not be
   messed up by function calls */
__asm__ (
    ".global shim_start \n"
    "  .type shim_start,@function \n"

    "shim_start: \n"
    "  movq %rsp, %rdi \n"
    "  call shim_main \n"
);

void shim_main(void* args) {
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
    int uid, gid;

    /* fetch environment information from aux vectors */
    const char ** e = envp;
    for (; *e ; e++)
        ;

    elf_auxv_t* auxp = (elf_auxv_t *)(e + 1);
    elf_auxv_t* av;
    for (av = auxp; av->a_type != AT_NULL; av++)
        switch (av->a_type) {
            case AT_UID:
            case AT_EUID:
                uid ^= av->a_un.a_val;
                break;
            case AT_GID:
            case AT_EGID:
                gid ^= av->a_un.a_val;
                break;
        }

    const char* loader_name   = (argv++)[0];
    const char* libc_location = (argv++)[0];
    const char* errstring = NULL;

    if (!loader_name) {
        errstring = "Something wrong with the command-line?";
        goto init_fail;
    }

    if (!libc_location) {
        errstring = "Need to specify the system library C location";
        goto init_fail;
    }

    int ret = init_loader(argv[0], libc_location);
    if (ret < 0) {
        errstring = "Unable to load the executable or the interpreter";
        goto init_fail;
    }

    start_execute(argc, argv, auxp);

    /* Should never reach here */
    return;

init_fail:
    printf("%s", errstring);
    printf("USAGE: %s libc_location executable args ...\n", loader_name);
    INLINE_SYSCALL(exit_group, 1, -1);
}
