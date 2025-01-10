#include <stdio.h>
#include "check.h"

int check_username(char* input) {
    if (strcmp(input, "tom"))
        return 0;
    else
        return 1;
}

int check_password(char* input) {
    if (strcmp(input, "654321"))
        return 0;
    else
        return 1;
}