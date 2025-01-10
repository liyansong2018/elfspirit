#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "check.h"

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s username password\n", argv[0]);
        exit(-1);
    }

    if (!check_username(argv[1])) {
        printf("Wrong username!\n");
    } else {
        if (!check_password(argv[2])) {
            printf("Wrong password!\n");
        } else {
            printf("Well done!\n");
        }
    }
    return 0;
}