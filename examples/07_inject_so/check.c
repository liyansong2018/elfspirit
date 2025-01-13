#include <stdio.h>
#include <string.h>
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

void decrypt(char *str) {
    char *ptr = str;
    
    while (*ptr != '\0') {
        if ((*ptr >= 'a' && *ptr <= 'w') || (*ptr >= 'A' && *ptr <= 'W')) {
            *ptr = *ptr + 3;
        } else if (*ptr == 'x') {
            *ptr = 'a';
        } else if (*ptr == 'y') {
            *ptr = 'b';
        } else if (*ptr == 'z') {
            *ptr = 'c';
        } else if (*ptr == 'X') {
            *ptr = 'A';
        } else if (*ptr == 'Y') {
            *ptr = 'B';
        } else if (*ptr == 'Z') {
            *ptr = 'C';
        } 
        
        ptr++;
    }
}