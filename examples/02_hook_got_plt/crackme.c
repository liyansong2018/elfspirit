#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// flag{YoU_goT_the_FlaG1216}
char password[] = "\x66\x6c\x61\x67\x7b\x59\x6f\x55\x5f\x67\x6f\x54\x5f\x74\x68\x65\x5f\x46\x6c\x61\x47\x31\x32\x31\x36\x7d";

int check(char* input) {
  for (int i = 0; i < sizeof(password) - 1; ++i) {
    password[i] ^= 0x0;
  }
  return memcmp(password, input, sizeof(password) - 1);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strlen(argv[1]) == (sizeof(password) - 1) && check(argv[1]) == 0) {
        printf("You got it !!\n");
        return EXIT_SUCCESS;
    }

    printf("Wrong\n");
    return EXIT_FAILURE;
}
