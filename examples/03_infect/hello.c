#include <stdio.h>

__attribute__((constructor)) void msg(int argc, char **argv) {
    printf("Hello, this is from constructor.\n");
}
 
int main() {
    puts("Hello, this is from main.");
    return 0;
}