#include <api.h>
#include <bpf-helper.h>
#include <shim_passthru.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <linux/prctl.h>

#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#ifndef SIGCHLD
# define SIGCHLD 17
#endif

int install_seccomp_filter(void* start, void* end) {
    int err = 0;
    struct bpf_labels labels = { .count = 0 };

    printf("set up filter in %p-%p\n", start, end);

    struct sock_filter filter[] = {
        IP,
        JLT((unsigned long) start, DENY),
        JGT((unsigned long) end,   DENY),

        SYSCALL(__NR_prctl,     DENY),
        ALLOW,
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    bpf_resolve_jumps(&labels, filter, prog.len);

    err = INLINE_SYSCALL(prctl, 5, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (IS_ERR(err))
        return -ERRNO(err);

    err = INLINE_SYSCALL(prctl, 3, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    if (IS_ERR(err))
        return -ERRNO(err);

    return 0;
}
