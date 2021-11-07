/*
 * @Author: your name
 * @Date: 2021-11-04 15:05:48
 * @LastEditTime: 2021-11-04 15:35:58
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /elf/delshtab.c
 */

#include <stdio.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "common.h"
#include "delsec.h"

/**
 * @description: Delete section header table
 * @param {char} *elf
 * @return {*}
 */
int delete_shtab(char *elf) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *elf_map_new;
    uint32_t shtab_size;

    MODE = get_elf_class(elf);

    fd = open(elf, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        ehdr = (Elf32_Ehdr *)elf_map;
        shtab_size = ehdr->e_shnum * sizeof(Elf32_Shdr);
        elf_map_new = delete_data(elf_map, st.st_size, ehdr->e_shoff, shtab_size);
        ehdr = (Elf32_Ehdr *)elf_map_new;
        ehdr->e_shnum = 0;
        ehdr->e_shoff = 0;
        ehdr->e_shentsize = 0;
        create_file(elf, elf_map_new, st.st_size - shtab_size);
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        ehdr = (Elf64_Ehdr *)elf_map;
        shtab_size = ehdr->e_shnum * sizeof(Elf64_Shdr);
        elf_map_new = delete_data(elf_map, st.st_size, ehdr->e_shoff, shtab_size);
        ehdr = (Elf64_Ehdr *)elf_map_new;
        ehdr->e_shnum = 0;
        ehdr->e_shoff = 0;
        ehdr->e_shentsize = 0;
        create_file(elf, elf_map_new, st.st_size - shtab_size);
    }

    free(elf_map_new);
    munmap(elf_map, st.st_size);
    close(fd);
    return 0;
}