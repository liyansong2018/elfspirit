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

/**
 * @description: delete data from ELF
 * @param {char} *elf_map
 * @param {uint32_t} file_size
 * @param {uint32_t} offset
 * @param {uint32_t} data_size
 * @return {*}
 */
char *delete_data(char *elf_map, uint32_t file_size, uint32_t offset, uint32_t data_size) {
    char *tmp;
    tmp = malloc(file_size - data_size);
    if (tmp < 0) {
        return NULL;
    }

    memcpy(tmp, elf_map, offset);
    memcpy(&tmp[offset], &elf_map[offset + data_size], file_size - data_size - offset);
    return tmp;
}

int delete_section(char *elf_name, char *section_name, char *config_name) {
    FILE *fp;
    int count = 0;
    char tmp_sec_name[LENGTH];
    char new_file[LENGTH];
    snprintf(new_file, LENGTH, "%s.new", elf_name);

    if (strlen(config_name) == 0) {
        printf("delete %s\n", tmp_sec_name);
        delete_section_imp(elf_name, section_name, 1);
        return 0;
    }
   
    fp = fopen(config_name, "r");
    if (fp <= 0) {
        perror("fopen");
        return -1;
    }
    
    while (!feof(fp)) {
        fgets(tmp_sec_name, LENGTH, fp);
        if ( tmp_sec_name[strlen(tmp_sec_name) - 1] == '\n')
            tmp_sec_name[strlen(tmp_sec_name) - 1] = '\0';  /* delete \n */
        printf("delete %s\n", tmp_sec_name);
        
        if (!count)
            delete_section_imp(elf_name, tmp_sec_name, 1);
        else {
            delete_section_imp(new_file, tmp_sec_name, 0);
        }
        count++;
    }
    fclose(fp);
}

int delete_section_imp(char *elf_name, char *section_name, int is_rename) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *elf_map_new;
    uint8_t *tmp_sec_name;

    fd = open(elf_name, O_RDONLY);
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
        Elf32_Shdr *shdr;
        Elf32_Phdr *phdr;
        Elf32_Shdr shstrtab;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                /* clean section */
                memset(elf_map + shdr[i].sh_offset, 0, shdr[i].sh_size);
                
                /* clean shstrtab */
                memset(tmp_sec_name, 0, strlen(tmp_sec_name));
                
                /* modify section header table number */
                ehdr->e_shnum--;

                /* modify section header string table index */
                if (i < ehdr->e_shstrndx) {
                    ehdr->e_shstrndx--;
                } else {
                    WARNING("Delete section header string table will result in a section header resolution error\n");
                    ehdr->e_shstrndx = 0;
                }            
                
                /* delete section header table */
                elf_map_new = delete_data(elf_map, st.st_size, ehdr->e_shoff + i * sizeof(Elf32_Shdr), sizeof(Elf32_Shdr));
                if (elf_map_new == NULL) {
                    WARNING("delete section header table error\n");
                    munmap(elf_map, st.st_size);
                    close(fd);
                    return -1;
                }             

                break;
            }
        }

        close(fd);
        create_file(elf_name, elf_map_new, st.st_size - sizeof(Elf32_Shdr), is_rename);
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr shstrtab;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                /* clean section */
                memset(elf_map + shdr[i].sh_offset, 0, shdr[i].sh_size);
                
                /* clean shstrtab */
                memset(tmp_sec_name, 0, strlen(tmp_sec_name));
                
                /* modify section header table number */
                ehdr->e_shnum--;

                /* modify section header string table index */
                if (i < ehdr->e_shstrndx) {
                    ehdr->e_shstrndx--;
                } else {
                    WARNING("Delete section header string table will result in a section header resolution error\n");
                    ehdr->e_shstrndx = 0;
                }            
                
                /* delete section header table */
                elf_map_new = delete_data(elf_map, st.st_size, ehdr->e_shoff + i * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr));
                if (elf_map_new == NULL) {
                    WARNING("delete section header table error\n");
                    munmap(elf_map, st.st_size);
                    close(fd);
                    return -1;
                }             

                break;
            }
        }

        close(fd);
        create_file(elf_name, elf_map_new, st.st_size - sizeof(Elf64_Shdr), is_rename);
    }

    free(elf_map_new);
    munmap(elf_map, st.st_size);
    
    return 0;
};