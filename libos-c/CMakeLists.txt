cmake_minimum_required(VERSION 2.8)

project(libos_c C ASM)

set(OMIT_FRAME_POINTER ON CACHE BOOL "Omit frame pointer")

include(../rules.cmake)

string(CONCAT CMAKE_C_FLAGS
    "-Wall -Wextra -fPIC -std=c11 -Winline -Wwrite-strings "
    "-fmerge-all-constants -Wstrict-prototypes -Wtrampolines "
    "-Werror=implicit-function-declaration "
    "-fno-stack-protector -fno-builtin -Wno-inline")

if(${OMIT_FRAME_POINTER})
    add_definitions("-DOMIT_FRAME_POINTER=1")
else()
    string(CONCAT CMAKE_C_FLAGS "-fno-omit-frame-point")
    add_definitions("-DOMIT_FRAME_POINTER=0")
endif()

string(CONCAT CMAKE_C_FLAGS_DEBUG
    "-gdwarf-2 -g3 -DDEBUG")
string(CONCAT CMAKE_ASM_FLAGS
    "-DASSEMBLER -Wa,--noexecstack -x assembler-with-cpp")
string(CONCAT CMAKE_SHARED_LINKER_FLAGS
    "-shared -nostdlib "
    "-Wl,-z,combreloc -Wl,-z,relro -Wl,-z,now -Wl,-z,defs "
    "-Wl,-T,${PROJECT_SOURCE_DIR}/shim.lds")

include_directories(.)

set(LIBOS_SOURCE
    syscall_trap.S
    shim_table.c
    shim_syscalls.c)

add_library(syscall SHARED
    ${LIBOS_SOURCE}
    ${PROJECT_SOURCE_DIR}/shim.map
    ${PROJECT_BINARY_DIR}/asm-offsets.h)

set_property(TARGET syscall APPEND_STRING PROPERTY LINK_FLAGS
    "-Wl,--version-script,${PROJECT_SOURCE_DIR}/shim.map")
