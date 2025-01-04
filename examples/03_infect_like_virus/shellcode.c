#include "arch/x86_64/syscall.c"
#define stdout 1

int my_print(const void* lhs, const void* rhs, int n) {
    const char msg[] = "This is shellcode!\n";
    _write(stdout, msg, sizeof(msg));
    return 0;
}