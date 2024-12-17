/*
 MIT License
 
 Copyright (c) 2024 Yansong Li
 
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

#define _GNU_SOURCE 1
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include "common.h"
#include "cJSON/cJSON.h"

/**
 * @brief 判断节头表是否在文件结尾
 * determine if section header table is at the end of the file
 * @param elfname elf file name
 * @return int result code {-1:error,0:false,1:true}
 */
static int is_shdr_end(char *elfname) {
    int fd;
    struct stat st;
    uint8_t *mapped;

    fd = open(elfname, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    mapped = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        ehdr = (Elf32_Ehdr *)mapped;
        if (ehdr->e_shoff +  ehdr->e_shnum * sizeof(Elf32_Shdr) == st.st_size) {
            goto TRUE;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        ehdr = (Elf64_Ehdr *)mapped;
        if (ehdr->e_shoff +  ehdr->e_shnum * sizeof(Elf64_Shdr) == st.st_size) {
            goto TRUE;
        }
    }

    close(fd);
    munmap(mapped, st.st_size);
    return 0;
TRUE:
    close(fd);
    munmap(mapped, st.st_size);
    return 1;
}

/**
 * @brief 将节头表移动到文件的另外一个位置
 * move the section header table to another location in the file
 * @param elfname elf file name
 * @param offset start address
 * @return int error code {-1:error,0:sucess}
 */
static int mov_shdr(char *elf_name, uint64_t offset) {
    int fd;
    struct stat st;
    void *mapped;
    size_t shdr_size;
    size_t file_size;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    mapped = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    file_size = st.st_size;

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)mapped;
        shdr_size = ehdr->e_shnum * sizeof(Elf32_Shdr);

        // 扩展文件大小
        file_size = file_size + shdr_size - (st.st_size - offset);
        ftruncate(fd, file_size);
        // 更新内存映射
        mapped = mremap(mapped, st.st_size, file_size, MREMAP_MAYMOVE);
        if (mapped == MAP_FAILED) {
            perror("mremap");
            goto ERR_EXIT;
        }
        ehdr = (Elf32_Ehdr *)mapped;
        // 拷贝节头表
        char *shdr_tmp = malloc(shdr_size);
        memcpy(shdr_tmp, mapped + ehdr->e_shoff, shdr_size);
        memcpy(mapped + offset, shdr_tmp, shdr_size);
        free(shdr_tmp);
        // 更新节头表的偏移
        ehdr->e_shoff = offset;
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mapped;
        shdr_size = ehdr->e_shnum * sizeof(Elf64_Shdr);

        // 扩展文件大小
        file_size = file_size + shdr_size - (st.st_size - offset);
        ftruncate(fd, file_size);
        // 更新内存映射
        mapped = mremap(mapped, st.st_size, file_size, MREMAP_MAYMOVE);
        if (mapped == MAP_FAILED) {
            perror("mremap");
            goto ERR_EXIT;
        }
        ehdr = (Elf64_Ehdr *)mapped;
        // 拷贝节头表
        char *shdr_tmp = malloc(shdr_size);
        memcpy(shdr_tmp, mapped + ehdr->e_shoff, shdr_size);
        memcpy(mapped + offset, shdr_tmp, shdr_size);
        free(shdr_tmp);
        // 更新节头表的偏移
        ehdr->e_shoff = offset;
    }

    close(fd);
    munmap(mapped, file_size);
    return 0;

ERR_EXIT:
    close(fd);
    munmap(mapped, file_size);
    return -1;
}

/**
 * @brief 增加一个节头表
 * add a section header table
 * @param elfname elf file name
 * @return int section index {-1:error,0:sucess}
 */
int add_shdr(char *elfname) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    uint64_t tmpsize;
    int index;

    fd = open(elfname, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    if (MODE == ELFCLASS32) {
        tmpsize = st.st_size + sizeof(Elf32_Shdr);
    }
    if (MODE == ELFCLASS64) {
        tmpsize = st.st_size + sizeof(Elf64_Shdr);
    }

    ftruncate(fd, tmpsize);
    mapped = mmap(0, tmpsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        ehdr = (Elf32_Ehdr *)mapped;
        shdr = (Elf32_Shdr *)&mapped[ehdr->e_shoff];
        ehdr->e_shnum += 1;
        index = ehdr->e_shnum - 1;
    }

    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        ehdr = (Elf64_Ehdr *)mapped;
        shdr = (Elf64_Shdr *)&mapped[ehdr->e_shoff];
        ehdr->e_shnum += 1;
        index = ehdr->e_shnum - 1;
    }

    close(fd);
    munmap(mapped, st.st_size);
    return index;
}

/**
 * @brief 增加一个节
 * add a section
 * @param elfname
 * @param size section size
 * @return int section index
 */
int add_section(char *elfname, size_t size) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    uint64_t secoffset; // segment offset
    int index;  // shdr index

    // 判断shdr是否在文件结尾
    // determine if SHDR is at the end of the file
    if(is_shdr_end(elfname) != 1) {
        VERBOSE("section header table is not at the end of the file\n");
        VERBOSE("move section header table\n");
        mov_shdr(elfname, get_file_size(elfname));
    } else {
        VERBOSE("section header table is at the end of the file\n");
    }

    // 节头表往后移size
    // move the section header table back size
    secoffset = get_shdr_offset(elfname);
    if (size) {
        mov_shdr(elfname, secoffset + size);
    }
    VERBOSE("move the shdr: %d\n", size);

    // 如果节头表在ELF文件末尾处，直接增加一个节头
    // if section header is at the end of elf
    index = add_shdr(elfname);
    VERBOSE("add a shdr: [%d]\n", index);

    // 设置新增的节的参数
    // set new segment args
    fd = open(elfname, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    mapped = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        ehdr = (Elf32_Ehdr *)mapped;
        shdr = (Elf32_Shdr *)&mapped[ehdr->e_shoff];
        // 增加节头的同时，又增加了节的大小，这时需要设置新增的节头参数
        // at the same time as adding a section header, the size of the section is also increased. 
        // in this case, it is necessary to set the parameters for the newly added section header.
        if (size) {
            shdr[index].sh_offset = secoffset;
            shdr[index].sh_size = size;
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        ehdr = (Elf64_Ehdr *)mapped;
        shdr = (Elf64_Shdr *)&mapped[ehdr->e_shoff];
        // 增加节头的同时，又增加了节的大小，这时需要设置新增的节头参数
        // at the same time as adding a section header, the size of the section is also increased. 
        // in this case, it is necessary to set the parameters for the newly added section header.
        if (size) {
            shdr[index].sh_offset = secoffset;
            shdr[index].sh_size = size;
        }
    }

    VERBOSE("add section successfully: [%d]\n", index);
    close(fd);
    munmap(mapped, st.st_size);
    return index;
}

/**
 * @brief Get the section content
 * 
 * @param elf_name original file name
 * @param section_name input argument: section name
 * @param section_info output argument: section content
 * @return error code {-1:error,0:sucess}
 */
int get_section(char *elf_name, char *section_name, char *section_info) {
    int fd;         // file descriptor
    int result;     // return result
    struct stat st;
    uint8_t *elf_map;
    uint8_t *name;
    int flag = 0;

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
        Elf32_Shdr shstrtab;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (validated_offset(name, elf_map, elf_map + st.st_size)) {
                ERROR("Corrupt file format\n");
                goto ERR_EXIT;
            }
            if (!strcmp(name, section_name)) {
                flag = 1;
                result = i;
                memcpy(section_info, &shdr[i], sizeof(Elf32_Shdr));
                break;
            }
        }
    }

    /* 64bit */
    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (validated_offset(name, elf_map, elf_map + st.st_size)) {
                ERROR("Corrupt file format\n");
                goto ERR_EXIT;
            }
            if (!strcmp(name, section_name)) {
                flag = 1;
                result = i;
                memcpy(section_info, &shdr[i], sizeof(Elf32_Shdr));
                break;
            }
        }
    }

    else {
        ERROR("Invalid ELF class");
        goto ERR_EXIT;
    }

    if (!flag) {
        ERROR("This file does not have %s\n", section_name);
        goto ERR_EXIT;
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return result;

ERR_EXIT:
    close(fd);
    munmap(elf_map, st.st_size);
    return -1;
};

/**
 * @brief Get the section address
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section address
 */
int get_section_addr(char *elf_name, char *section_name) {
    if (MODE == ELFCLASS32) {
        Elf32_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_addr;
    } else if (MODE == ELFCLASS64) {
        Elf64_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_addr;
    }
}

/**
 * @brief Get the section file offset address
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section file offset address
 */
int get_section_offset(char *elf_name, char *section_name) {
    if (MODE == ELFCLASS32) {
        Elf32_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_offset;
    } else if (MODE == ELFCLASS64) {
        Elf64_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_offset;
    }
}

/**
 * @brief Get the section size
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section size
 */
size_t get_section_size(char *elf_name, char *section_name) {
    if (MODE == ELFCLASS32) {
        Elf32_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_size;
    } else if (MODE == ELFCLASS64) {
        Elf64_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_size;
    }
}

/**
 * @brief Get the section index
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section index
 */
int get_section_index(char *elf_name, char *section_name) {
    Elf64_Shdr section_info;
    return get_section(elf_name, section_name, &section_info);
}
