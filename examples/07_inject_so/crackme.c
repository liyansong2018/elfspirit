#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "check.h"

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s username password\n", argv[0]);
        exit(-1);
    }

    char flag[100] = "cixd{Vlr_Dlq_cfopq_irzhv_ZEXOJ_lc_2023}";

    if (!check_username(argv[1])) {
        printf("Wrong username!\n");
    } else {
        if (!check_password(argv[2])) {
            printf("Wrong password!\n");
        } else {
            decrypt(flag);
            printf("%s\n", flag);
        }
    }

    getchar();  // pause to cat /proc/pid/maps | grep crackme.bin
    return 0;
}