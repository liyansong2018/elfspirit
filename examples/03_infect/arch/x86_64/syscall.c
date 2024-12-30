// write syscall
static long _write(long fd, const char *buf, unsigned long len) {

    register long ret asm ("rax");
    register int sys_write asm ("rax") = 1;
    register long _fd asm ("rdi") = fd;
    register const char* _buf asm ("rsi") = buf;
    register unsigned long _len asm ("rdx") = len;
    asm volatile (
        "syscall;"
        : "=r" (ret)
        : "r" (sys_write), "r" (_fd), "r" (_buf), "r" (_len)
        :
    );
    return ret;
}

// exit syscall
static long _exit(int errcode) {

    register long ret asm ("rax");
    register int sys_exit asm ("rax") = 60;
    register int _errcode asm ("rdi") = errcode;
    asm volatile (
        "syscall;"
        : "=r" (ret)
        : "r" (sys_exit), "r" (_errcode)
        :
    );
    return ret;
}