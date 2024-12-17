/*
 MIT License
 
 Copyright (c) 2021 Yansong Li
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
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
        create_file(elf, elf_map_new, st.st_size - shtab_size, 1);
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
        create_file(elf, elf_map_new, st.st_size - shtab_size, 1);
    }

    free(elf_map_new);
    munmap(elf_map, st.st_size);
    close(fd);
    return 0;
}
