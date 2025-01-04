#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef int(*check_t)(char*);

int main (int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s password\n", argv[0]);
        exit(-1);
    }

    void* handler = dlopen("./crackme.bin", RTLD_LAZY);
    if (!handler) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return 1;
    }

    check_t check_password = (check_t)dlsym(handler, "check_password");
    if (check_password == NULL) {
        fprintf(stderr, "dlsym error: %s\n", dlerror());
        return 1;
    }

    int output = check_password(argv[1]);

    printf("Output of check_password('%s'): %d\n", argv[1], output);

    return 0;
}
