# Passthru Library OS

The Passthru library OS is a basic framework for implementing more sophisticated userspace
emulation and privilege separation logic. The library OS contains the system call traps for
the system library C (i.e., libc), and skeleton code for implementing system calls with
low-level host system APIs.

The current Passthru library OS is a derivative work the Graphene library OS: <https://github.com/oscarlab/graphene>.

### Code Structure

The Passthru library OS contains several subprojects:
- glibc: This directory contains the script for downloading and building GNU libc 2.27 and
  the patches for basic system call trapping
- libos-c: This directory contains the library OS implementation in C for forwarding the
  system calls to the kernel. This specific implementation does not link with libc internally.

### Compilation

To build the Passthru library OS, the user must first build the GNU libc:

```
cd glibc
cmake .
make
```

The built GNU libc will be installed in the `glibc/glibc-install` directory. Then, we will
build the library OS itself:

```
cd ../libos-c
cmake .
make
```

The command above will build a binary called `libsyscall.so` if compiled successfully. This
binary serves as the loader for bootstrapping the GNU libc and the system call forwarding
mechanism.

### Testing

To test the Passthru library OS, first build the test programs in the `tests` directory:
```
cd ../tests
make
```

Then, run the test programs with the library OS (working as a loader), along with the patched
GNU libc given from the commandline:
```
../libos-c/libsyscall.so ../glibc/glibc-install/lib hello
```
```
