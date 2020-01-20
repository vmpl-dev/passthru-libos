cmake_minimum_required(VERSION 2.8)

project(glibc)

include(ExternalProject)
include(${PROJECT_SOURCE_DIR}/../rules.cmake)

set(GLIBC_MIRRORS
    "https://ftp.gnu.org/gnu/glibc"
    "https://mirrors.kernel.org/gnu/glibc"
    "https://mirrors.ocf.berkeley.edu/gnu/glibc"
    CACHE STRING "GLIBC mirrors")

set(GLIBC_VERSION 2.27 CACHE STRING "GLIBC version")
set(GLIBC_NAME glibc-${GLIBC_VERSION})
set(GLIBC_CFLAGS "-gdwarf-2 -g3 -O2 -U_FORTIFY_SOURCE -Wno-unused-value")
set(GLIBC_CONFIGURE_OPTIONS --with-tls --without-selinux
    --disable-test --disable-nscd --disable-sanity-checks)
separate_arguments(GLIBC_CONFIGURE_OPTIONS)

if(${CMAKE_VERSION} VERSION_GREATER "3.6.0")
    append_list(GLIBC_URLS "/${GLIBC_NAME}.tar.gz" ${GLIBC_MIRRORS})
else()
    # For CMake < 3.6.0, ExternalProject does not support multiple URLs
    list(GET GLIBC_MIRRORS 0 FIRST_MIRROR)
    set(GLIBC_URLS ${FIRST_MIRROR}/${GLIBC_NAME}.tar.gz)
endif()

set(GLIBC_COMMON_PATCHES
    glibc-patches/${GLIBC_NAME}.patch
    glibc-patches/${GLIBC_NAME}-debug.patch
    glibc-patches/syscall-trap.patch)

if(EXISTS ${PROJECT_SOURCE_DIR}/${GLIBC_NAME}.cmake)
    include(${PROJECT_SOURCE_DIR}/${GLIBC_NAME}.cmake)
else()
    message(FATAL_ERROR  "Not a supported GLIBC version: ${GLIBC_VERSION}")
endif()

set(PATCH_COMMANDS "")
foreach(PATCH ${GLIBC_COMMON_PATCHES} ${GLIBC_PATCHES})
    list(APPEND PATCH_COMMANDS
        patch -p1 < ${PROJECT_SOURCE_DIR}/${PATCH} &&)
endforeach()

list(APPEND PATCH_COMMANDS
    echo "All patches applied.")

set(GLIBC_BUILD_DIR ${PROJECT_BINARY_DIR}/glibc-build)

ExternalProject_Add(${GLIBC_NAME}
    URL
        "${GLIBC_URLS}"
    URL_HASH
        SHA256=${GLIBC_HASH}
    SOURCE_DIR
        ${PROJECT_BINARY_DIR}/${GLIBC_NAME}
    BINARY_DIR
        ${GLIBC_BUILD_DIR}
    PREFIX
        ${GLIBC_BUILD_DIR}
    INSTALL_DIR
        ${PROJECT_BINARY_DIR}/glibc-install
    PATCH_COMMAND
        ${PATCH_COMMANDS}
    CONFIGURE_COMMAND
        <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>/ ${GLIBC_CONFIGURE_OPTIONS} "CFLAGS=${GLIBC_CFLAGS}"
)

set_property(DIRECTORY PROPERTY
    ADDITIONAL_MAKE_CLEAN_FILES
    ${PROJECT_BINARY_DIR}/${GLIBC_NAME} ${GLIBC_BUILD_DIR} APPEND)
