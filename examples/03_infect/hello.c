#include <stdio.h>

__attribute__((constructor)) void msg(int argc, char **argv) {
    printf("Hello, this is constructor.\n");
}
 
int main() {
    puts("Hello, this is main.");
    return 0;
}