#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Test-only process-tree restriction: force the original optional-syscall
 * fallback without a mutable observer hook or any production option. */
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_statx, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = {
        .len = sizeof(instructions) / sizeof(instructions[0]),
        .filter = instructions,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)) {
        perror("install test statx restriction");
        return 3;
    }
    struct statx st;
    errno = 0;
    if (syscall(SYS_statx, AT_FDCWD, "/proc", 0, STATX_MNT_ID, &st) != -1 || errno != ENOSYS) {
        fputs("statx restriction not observed\n", stderr);
        return 4;
    }
    puts("INACTIVE_PROC_FORCED_STATX_ENOSYS observed=true process_tree_only=true");
    if (fflush(stdout)) return 5;
    execv(argv[1], argv + 1);
    perror("exec original native test");
    return 6;
}
