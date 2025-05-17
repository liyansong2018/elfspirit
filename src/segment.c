/*
 MIT License
 
 Copyright (c) 2024 SecNotes
 
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
#include "segment.h"
#include "cJSON/cJSON.h"

/**
 * @brief 获取程序头表的load下标
 * get program header table load index
 * @return section address
 */
static int get_phdr_load(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    int index;

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

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
        Elf32_Phdr *phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                if (phdr[i].p_offset == ehdr->e_phoff) {
                    index = i;
                    break;
                } 
            }
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
        Elf64_Phdr *phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                if (phdr[i].p_offset == ehdr->e_phoff) {
                    index = i;
                    break;
                }   
            }
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return index;
}

/**
 * @brief 得到段的映射地址范围
 * Obtain the mapping address range of the segment
 * @param elf_name 
 * @param type segment type
 * @param start output args
 * @param end output args
 * @return int error code {-1:error,0:sucess}
 */
int get_segment_range(char *elf_name, int type, uint64_t *start, uint64_t *end) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint64_t low = 0xffffffff;
    uint64_t high = 0;

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

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
        Elf32_Phdr *phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        // 计算地址的最大值和最小值
        // calculate the maximum and minimum values of the virtual address
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == type) {
                if (phdr[i].p_vaddr < low)
                    low = phdr[i].p_vaddr;
                if (phdr[i].p_vaddr + phdr[i].p_memsz > high)
                    high = phdr[i].p_vaddr + phdr[i].p_memsz;
            }
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
        Elf64_Phdr *phdr = (Elf64_Phdr *)&elf_map[ehdr->e_phoff];
        // 计算地址的最大值和最小值
        // calculate the maximum and minimum values of the virtual address
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == type) {
                if (phdr[i].p_vaddr < low)
                    low = phdr[i].p_vaddr;
                if (phdr[i].p_vaddr + phdr[i].p_memsz > high)
                    high = phdr[i].p_vaddr + phdr[i].p_memsz;
            }
        }
    }

    *start = low;
    *end = high; 

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

/**
 * @brief 判断phdr是否在文件结尾
 * determine if PHDR is at the end of the file
 * @param elf_name elf file name
 */
static int is_phdr_end(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *mapped;

    fd = open(elf_name, O_RDWR);
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
        if (ehdr->e_phoff +  ehdr->e_phnum * sizeof(Elf32_Phdr) == st.st_size) {
            goto TRUE;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        ehdr = (Elf64_Ehdr *)mapped;
        if (ehdr->e_phoff +  ehdr->e_phnum * sizeof(Elf64_Phdr) == st.st_size) {
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
 * @brief 将程序头表移动到文件的另外一个位置
 * move the program header table to another location in the file
 * @param elf_name elf file name
 * @param offset start address
 * @param need_load add a paragraph pointing to PHDR itself
 * @return int error code {-1:error,0:sucess}
 */
static int mov_phdr(char *elf_name, uint64_t offset, int need_load) {
    int fd;
    struct stat st;
    void *mapped;
    uint64_t phdr_start;
    uint64_t phdr_end;
    size_t phdr_size;
    size_t file_size;

    // 计算LOAD段的地址空间范围
    // calculate the address space range of the LOAD segment
    uint64_t vstart, vend;
    get_segment_range(elf_name, PT_LOAD, &vstart, &vend);
    DEBUG("LOAD vstart: 0x%x ~ vend: 0x%x\n", vstart, vend);

    // 得到程序头表下标
    // get phdr index
    int phdr_i = get_phdr_load(elf_name);

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
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr_size = ehdr->e_phnum * sizeof(Elf32_Phdr);
        phdr_start = ehdr->e_phoff;
        phdr_end = ehdr->e_phoff + phdr_size;

        // 扩展文件大小
        file_size = file_size + phdr_size - (st.st_size - offset);
        // 是否要增加一个段，指向phdr本身
        if (need_load)
            file_size += sizeof(Elf32_Phdr);
        ftruncate(fd, file_size);
        // 更新内存映射
        mapped = mremap(mapped, st.st_size, file_size, MREMAP_MAYMOVE);
        if (mapped == MAP_FAILED) {
            perror("mremap");
            goto ERR_EXIT;
        }
        ehdr = (Elf32_Ehdr *)mapped;
        // 拷贝程序头
        char *phdr_tmp = malloc(phdr_size);
        memcpy(phdr_tmp, mapped + ehdr->e_phoff, phdr_size);
        memcpy(mapped + offset, phdr_tmp, phdr_size);
        free(phdr_tmp);
        // 更新程序头的偏移
        // phdr_start = st.st_size;
        // phdr_size += sizeof(Elf32_Phdr);   // 同时需要增加一个LOAD段
        // phdr_end = phdr_start + phdr_size;
        ehdr->e_phoff = offset;
        if (need_load) {
            // 同时需要增加一个LOAD段
            ehdr->e_phnum += 1;
            phdr_size += sizeof(Elf32_Phdr);
        }
                           
        // PHDR的第一个表项，指向PHDR本身，主要是为了告诉加载器，PHDR本身应该映射到进程地址空间，以便程序本身可以访问它们
        // The PHDR pointing to the PHDRs tells the loader that the PHDRs themselves should be mapped 
        // to the process address space, in order to make them accessible to the program itself.
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
        phdr[0].p_offset = offset;
        // relationship between VMA, file offset, and alignment:
        // virtual_adress % alignment == file_offset % aligment
        phdr[0].p_vaddr = align_to_4k(vend) + offset % PAGE_SIZE; // 需要设置4K对齐
        phdr[0].p_paddr = phdr[0].p_vaddr;
        phdr[0].p_filesz = phdr_size;
        phdr[0].p_memsz = phdr_size;
        // 设置增加的段的参数
        if (need_load) {
            phdr_i = ehdr->e_phnum - 1;
        }
        phdr[phdr_i].p_type = PT_LOAD;
        phdr[phdr_i].p_offset = ehdr->e_phoff;
        phdr[phdr_i].p_vaddr = phdr[0].p_vaddr;
        phdr[phdr_i].p_paddr = phdr[0].p_vaddr;
        phdr[phdr_i].p_filesz = phdr_size;
        phdr[phdr_i].p_memsz = phdr_size;
        phdr[phdr_i].p_flags = 4;
        phdr[phdr_i].p_align = 4096; 
}

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr_size = ehdr->e_phnum * sizeof(Elf64_Phdr);
        phdr_start = ehdr->e_phoff;
        phdr_end = ehdr->e_phoff + phdr_size;

        // 扩展文件大小
        file_size = file_size + phdr_size - (st.st_size - offset);
        // 是否要增加一个段，指向phdr本身
        if (need_load)
            file_size += sizeof(Elf64_Phdr);
        ftruncate(fd, file_size);
        // 更新内存映射
        mapped = mremap(mapped, st.st_size, file_size, MREMAP_MAYMOVE);
        if (mapped == MAP_FAILED) {
            perror("mremap");
            goto ERR_EXIT;
        }
        ehdr = (Elf64_Ehdr *)mapped;
        // 拷贝程序头
        char *phdr_tmp = malloc(phdr_size);
        memcpy(phdr_tmp, mapped + ehdr->e_phoff, phdr_size);
        memcpy(mapped + offset, phdr_tmp, phdr_size);
        free(phdr_tmp);
        // 更新程序头的偏移
        // phdr_start = st.st_size;
        // phdr_size += sizeof(Elf64_Phdr);   // 同时需要增加一个LOAD段
        // phdr_end = phdr_start + phdr_size;
        ehdr->e_phoff = offset;
        if (need_load) {
            // 同时需要增加一个LOAD段
            ehdr->e_phnum += 1;
            phdr_size += sizeof(Elf64_Phdr);
        }
                           
        // PHDR的第一个表项，指向PHDR本身，主要是为了告诉加载器，PHDR本身应该映射到进程地址空间，以便程序本身可以访问它们
        // The PHDR pointing to the PHDRs tells the loader that the PHDRs themselves should be mapped 
        // to the process address space, in order to make them accessible to the program itself.
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];
        phdr[0].p_offset = offset;
        // relationship between VMA, file offset, and alignment:
        // virtual_adress % alignment == file_offset % aligment
        phdr[0].p_vaddr = align_to_4k(vend) + offset % PAGE_SIZE; // 需要设置4K对齐
        phdr[0].p_paddr = phdr[0].p_vaddr;
        phdr[0].p_filesz = phdr_size;
        phdr[0].p_memsz = phdr_size;
        // 设置增加的段的参数
        if (need_load) {
            phdr_i = ehdr->e_phnum - 1;
        }
        phdr[phdr_i].p_type = PT_LOAD;
        phdr[phdr_i].p_offset = ehdr->e_phoff;
        phdr[phdr_i].p_vaddr = phdr[0].p_vaddr;
        phdr[phdr_i].p_paddr = phdr[0].p_vaddr;
        phdr[phdr_i].p_filesz = phdr_size;
        phdr[phdr_i].p_memsz = phdr_size;
        phdr[phdr_i].p_flags = 4;
        phdr[phdr_i].p_align = 4096; 
    }

    close(fd);
    munmap(mapped, file_size);
    return phdr_start;

ERR_EXIT:
    close(fd);
    munmap(mapped, file_size);
    return -1;
}

/**
 * @brief 增加一个程序头表
 * add a program header table
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess}
 */
int add_phdr_entry(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    uint64_t tmpsize;
    int index;

    index = get_phdr_load(elf_name);
    VERBOSE("get the phdr load index: [%d]\n", index);

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    if (MODE == ELFCLASS32) {
        tmpsize = st.st_size + sizeof(Elf32_Phdr);
    }
    if (MODE == ELFCLASS64) {
        tmpsize = st.st_size + sizeof(Elf64_Phdr);
    }

    ftruncate(fd, tmpsize);
    mapped = mmap(0, tmpsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
        ehdr->e_phnum += 1;
        phdr[0].p_filesz += sizeof(Elf32_Phdr);
        phdr[0].p_memsz = phdr[0].p_filesz;
        phdr[index].p_filesz = phdr[0].p_filesz;
        phdr[index].p_memsz = phdr[0].p_filesz;
    }

    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];
        ehdr->e_phnum += 1;
        phdr[0].p_filesz += sizeof(Elf64_Phdr);
        phdr[0].p_memsz = phdr[0].p_filesz;
        phdr[index].p_filesz = phdr[0].p_filesz;
        phdr[index].p_memsz = phdr[0].p_filesz;
    }

    close(fd);
    munmap(mapped, st.st_size);
    return 0;
}

/**
 * @brief 增加一个段
 * add a segment
 * @param elf_name 
 * @param type segment type
 * @param size segment size
 * @return int segment index
 */
int add_segment(char *elf_name, int type, size_t size) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    uint64_t segoffset; // segment offset
    int index;  // phdr load index

    // 判断phdr是否在文件结尾
    // determine if PHDR is at the end of the file
    if(is_phdr_end(elf_name) != 1) {
        VERBOSE("program header table is not at the end of the file\n");
        VERBOSE("move program header table\n");
        mov_phdr(elf_name, get_file_size(elf_name), 1);
    } else {
        VERBOSE("program header table is at the end of the file\n");
    }

    // 程序头往后移size
    // move the program header table back size
    segoffset = get_phdr_offset(elf_name);
    mov_phdr(elf_name, segoffset + size, 0);
    VERBOSE("move the phdr: %d\n", size);

    // 如果程序头在ELF文件末尾处，直接增加一个程序头表项
    // if program header is at the end of elf
    add_phdr_entry(elf_name);
    VERBOSE("add a phdr\n");

    // 计算LOAD段的地址空间范围
    // calculate the address space range of the LOAD segment
    uint64_t vstart, vend;
    get_segment_range(elf_name, type, &vstart, &vend);

    // 设置新增的段的参数
    // set new segment args
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

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
        phdr[ehdr->e_phnum - 1].p_filesz = size;
        phdr[ehdr->e_phnum - 1].p_memsz = size;
        phdr[ehdr->e_phnum - 1].p_offset = segoffset;
        phdr[ehdr->e_phnum - 1].p_vaddr = align_to_4k(vend) + segoffset % PAGE_SIZE;
        phdr[ehdr->e_phnum - 1].p_paddr = phdr[ehdr->e_phnum - 1].p_vaddr;
        phdr[ehdr->e_phnum - 1].p_type = PT_LOAD;
        phdr[ehdr->e_phnum - 1].p_flags = 4;    // default read permission
        index = ehdr->e_phnum - 1;
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];
        phdr[ehdr->e_phnum - 1].p_filesz = size;
        phdr[ehdr->e_phnum - 1].p_memsz = size;
        phdr[ehdr->e_phnum - 1].p_offset = segoffset;
        phdr[ehdr->e_phnum - 1].p_vaddr = align_to_4k(vend) + segoffset % PAGE_SIZE;
        phdr[ehdr->e_phnum - 1].p_paddr = phdr[ehdr->e_phnum - 1].p_vaddr;
        phdr[ehdr->e_phnum - 1].p_type = PT_LOAD;
        phdr[ehdr->e_phnum - 1].p_flags = 4;    // default read permission
        index = ehdr->e_phnum - 1;
    }

    VERBOSE("add segment successfully: [%d]\n", index);
    close(fd);
    munmap(mapped, st.st_size);
    return index;
}

/**
 * @brief 增加一个段，并填充内容
 * add a paragraph and fill in the content
 * @param elf_name 
 * @param type segment type
 * @param content segment content
 * @param size segment size
 * @return int segment index {-1:error}
 */
int add_segment_content(char *elf_name, int type, char *content, size_t size) {
    int i = add_segment(elf_name, type, size);
    uint64_t offset = get_segment_offset(elf_name, i);
    if (set_content(elf_name, offset, content, size)) {
        return -1;
    } else {
        return i;
    }
}

/**
 * @brief 增加一个段，并用文件填充内容
 * add a paragraph and fill in the content with a file
 * @param elf_name 
 * @param type segment type
 * @param file file content
 * @return int segment index {-1:error}
 */
int add_segment_file(char *elf_name, int type, char *file) {
    char* buffer = NULL;
    int file_size = read_file(file, &buffer);
    if (file_size > 0) {
        DEBUG("file size: 0x%x\n", file_size);
    } else {
        DEBUG("error: Unable to read file %s\n", file);
        goto ERR_EXIT;
    }

    int i = add_segment(elf_name, type, file_size);
    uint64_t offset = get_segment_offset(elf_name, i);
    if (set_content(elf_name, offset, buffer, file_size)) {
        DEBUG("set content");
        goto ERR_EXIT;
    }

    if (buffer != NULL) {
        free(buffer);
    }
    return i;

ERR_EXIT:
    if (buffer != NULL) {
        free(buffer);
    }
    return -1;
}

/**
 * @brief 根据段的下标，获取段表头
 * obtain the program header table based on its index
 * @param elfname 
 * @param i segment index
 * @return int error code {-1:error,0:sucess}
 */
static int get_segment(char *elfname, int i, char *segment_info) {
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

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
        memcpy(segment_info, &phdr[i], sizeof(Elf32_Phdr));
    }

    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];
        memcpy(segment_info, &phdr[i], sizeof(Elf64_Phdr));
    }

    close(fd);
    munmap(mapped, st.st_size);
    return 0;
}

/**
 * @brief 根据段的下标，获取段的偏移
 * obtain the offset of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment offset
 */
uint64_t get_segment_offset(char *elfname, int i) {
    if (MODE == ELFCLASS32) {
        Elf32_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_offset;
    } else if (MODE == ELFCLASS64) {
        Elf64_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_offset;
    }
}

/**
 * @brief 根据段的下标，获取段的虚拟地址
 * obtain the vaddr of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment vaddr
 */
uint64_t get_segment_vaddr(char *elfname, int i) {
    if (MODE == ELFCLASS32) {
        Elf32_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_vaddr;
    } else if (MODE == ELFCLASS64) {
        Elf64_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_vaddr;
    }
}

/**
 * @brief 根据段的下标，获取段的物理地址
 * obtain the paddr of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment vaddr
 */
uint64_t get_segment_paddr(char *elfname, int i) {
    if (MODE == ELFCLASS32) {
        Elf32_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_paddr;
    } else if (MODE == ELFCLASS64) {
        Elf64_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_paddr;
    }
}

/**
 * @brief 根据段的下标，获取段的文件大小
 * obtain the filesz of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment filesz
 */
uint64_t get_segment_filesz(char *elfname, int i) {
    if (MODE == ELFCLASS32) {
        Elf32_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_filesz;
    } else if (MODE == ELFCLASS64) {
        Elf64_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_filesz;
    }
}

/**
 * @brief 根据段的下标，获取段的内存大小
 * obtain the memsz of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment memsz
 */
uint64_t get_segment_memsz(char *elfname, int i) {
    if (MODE == ELFCLASS32) {
        Elf32_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_memsz;
    } else if (MODE == ELFCLASS64) {
        Elf64_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_memsz;
    }
}

/**
 * @brief 根据段的下标，获取段的类型
 * obtain the type of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment type
 */
uint64_t get_segment_type(char *elfname, int i) {
    if (MODE == ELFCLASS32) {
        Elf32_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_type;
    } else if (MODE == ELFCLASS64) {
        Elf64_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_type;
    }
}

/**
 * @brief 根据段的下标，获取段的权限标志
 * obtain the permission of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment flags
 */
uint64_t get_segment_flags(char *elfname, int i) {
    if (MODE == ELFCLASS32) {
        Elf32_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_flags;
    } else if (MODE == ELFCLASS64) {
        Elf64_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_flags;
    }
}

/**
 * @brief 根据段的下标，获取段的对齐方式
 * obtain the align of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment align
 */
uint64_t get_segment_align(char *elfname, int i) {
    if (MODE == ELFCLASS32) {
        Elf32_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_align;
    } else if (MODE == ELFCLASS64) {
        Elf64_Phdr segment_info;
        get_segment(elfname, i, &segment_info);
        return segment_info.p_align;
    }
}

/**
 * @brief 根据dynamic段的tag，得到或者设置值
 * get or set dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @param option {GET, SET, INDEX}
 * @return int error code {-1:error,0:sucess}
 */
static int opt_dynamic_segment(char *elfname, int tag, uint64_t *value, enum OPT_FUNCTION opt) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    int result = -1;

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
        Elf32_Phdr *phdr;
        Elf32_Dyn *dyn;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                dyn = (Elf32_Dyn *)(mapped + phdr[i].p_offset);
                for (uint64_t j = 0; j < phdr[i].p_filesz / sizeof(Elf32_Dyn); j++) {
                    if (dyn[j].d_tag == tag) {
                        switch (opt)
                        {
                            case GET_SEG:
                                *value = dyn[j].d_un.d_val;
                                result = 0;
                                break;
                            
                            case SET_SEG:
                                printf("%x->%x\n", dyn[j].d_un.d_val, *value);
                                dyn[j].d_un.d_val = *value;
                                result = 0;
                                break;
                            
                            case INDEX_SEG:
                                *value = j;
                                result = 0;
                                break;
                            
                            default:
                                result = -1;
                                break;
                        }

                        break;
                    }
                }
                break;
            }
        }
    }

    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Dyn *dyn;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                dyn = (Elf64_Dyn *)(mapped + phdr[i].p_offset);
                for (uint64_t j = 0; j < phdr[i].p_filesz / sizeof(Elf64_Dyn); j++) {
                    if (dyn[j].d_tag == tag) {
                        switch (opt)
                        {
                            case GET_SEG:
                                *value = dyn[j].d_un.d_val;
                                result = 0;
                                break;
                            
                            case SET_SEG:
                                printf("%x->%x\n", dyn[j].d_un.d_val, *value);
                                dyn[j].d_un.d_val = *value;
                                result = 0;
                                break;
                            
                            case INDEX_SEG:
                                *value = j;
                                result = 0;
                                break;
                            
                            default:
                                result = -1;
                                break;
                        }

                        break;
                    }
                }
                break;
            }
        }
    }

    close(fd);
    munmap(mapped, st.st_size);
    return result;
}

/**
 * @brief 根据dynamic段的tag，得到值
 * get dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @return int error code {-1:error,0:sucess}
 */
uint64_t get_dynamic_value_by_tag(char *elfname, int tag, uint64_t *value) {
    return opt_dynamic_segment(elfname, tag, value, GET_SEG);
}

/**
 * @brief 根据dynamic段的tag，设置值
 * set dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @return int error code {-1:error,0:sucess}
 */
uint64_t set_dynamic_value_by_tag(char *elfname, int tag, uint64_t *value) {
    return opt_dynamic_segment(elfname, tag, value, SET_SEG);
}

/**
 * @brief 根据dynamic段的tag，得到下标
 * get dynamic segment index by tag
 * @param elfname 
 * @param tag dynamic item tag
 * @param index dynamic item index
 * @return dynamic item index {-1:error,0:sucess}
 */
uint64_t get_dynamic_index_by_tag(char *elfname, int tag, uint64_t *index) {
    return opt_dynamic_segment(elfname, tag, index, INDEX_SEG);
}

/**
 * @brief 根据tag判断某个动态item是否存在
 * determine whether a dynamic item exists based on the tag
 * @param elfname 
 * @param tag dynamic item tag
 * @return dynamic item index {-1:false, other:true}
 */
int has_dynamic_by_tag(char *elfname, int tag) {
    // use uint64_t instead of int: avoid overflow
    uint64_t index = -1;
    get_dynamic_index_by_tag(elfname, tag, &index);
    if (index == -1)
        return -1;
    else 
        return index;
}

/**
 * @brief 扩充一个节或者一个段，通过将节或者段移动到文件末尾实现。
 * expand a section or segment by moving it to the end of the file.
 * @param elfname 
 * @param offset sec/seg offset
 * @param org_size sec/seg origin size
 * @param add_content new added content
 * @param content_size new added content size
 * @return segment index {-1:error}
 */
int expand_segment(char *elfname, uint64_t offset, size_t org_size, char *add_content, size_t content_size) {
    int fd;     // file descriptor
    char *buf;  // new content
    int i;      // segment index

    // 打开文件
    // open the file
    fd = open(elfname, O_RDONLY);

    if (fd == -1) {
        perror("Failed to open file");
        return -1;
    }

    // 设置文件偏移量
    // set the file offset
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("Failed to set file offset");
        close(fd);
        return -1;
    }

    // 从指定偏移处读取数据
    // read data from the offset file
    buf = malloc(org_size + content_size);
    ssize_t bytes_read = read(fd, buf, org_size);
    if (bytes_read == -1) {
        perror("Failed to read from file");
        close(fd);
        free(buf);
        return -1;
    }

    memcpy(buf + org_size, add_content, content_size);
    i = add_segment_content(elfname, PT_LOAD, buf, org_size + content_size);

    // 关闭文件
    // close the file
    close(fd);
    free(buf);
    return i;
}

/**
 * @brief 扩充dynstr段，通过将节或者段移动到文件末尾实现。
 * expand dynstr segment by moving it to the end of the file.
 * @param elfname 
 * @param str new dynstr item
 * @return segment index {-1:error}
 */
int expand_dynstr_segment(char *elfname, char *str) {
    // get offset and size
    uint64_t addr, offset;
    size_t size;
    int seg_i, sec_i;
    get_dynamic_value_by_tag(elfname, DT_STRTAB, &addr);
    get_dynamic_value_by_tag(elfname, DT_STRSZ, &size);
    VERBOSE("dynamic strtab addr: 0x%x, size: 0x%x\n", addr, size);

    // copy
    // fix error in expanding segment if addr != offset
    offset = get_section_offset(elfname, ".dynstr");
    seg_i = expand_segment(elfname, offset, size, str, strlen(str) + 1);

    // set phdr
    VERBOSE("set phdr\n");
    addr = get_segment_vaddr(elfname, seg_i);
    offset = get_segment_offset(elfname, seg_i);
    size = get_segment_memsz(elfname, seg_i);
    set_dynamic_value_by_tag(elfname, DT_STRTAB, &addr);
    set_dynamic_value_by_tag(elfname, DT_STRSZ, &size);
    
    // set shdr
    VERBOSE("set shdr\n");
    sec_i = get_section_index(elfname, ".dynstr");
    set_section_off(elfname, sec_i, offset);
    set_section_addr(elfname, sec_i, addr);
    set_section_size(elfname, sec_i, size);
    return seg_i;
}

/**
 * @brief 扩充strtab，通过将节移动到文件末尾实现。
 * expand strtab section by moving it to the end of the file.
 * @param elfname 
 * @param str new strtab item
 * @return section index {-1:error}
 */
int expand_strtab_section(char *elfname, char *str) {
    uint64_t offset,addr;
    size_t size;
    int sec_i, seg_i;

    // copy
    offset = get_section_offset(elfname, ".strtab");
    size = get_section_size(elfname, ".strtab");
    VERBOSE("strtab offset: 0x%x, size: 0x%x\n", offset, size);

    // expand section
    seg_i = expand_segment(elfname, offset, size, str, strlen(str) + 1);
    addr = get_segment_vaddr(elfname, seg_i);
    offset = get_segment_offset(elfname, seg_i);
    size = get_segment_memsz(elfname, seg_i);
    
    // set shdr
    VERBOSE("set shdr\n");
    sec_i = get_section_index(elfname, ".strtab");
    set_section_off(elfname, sec_i, offset);
    set_section_addr(elfname, sec_i, addr);
    set_section_size(elfname, sec_i, size);
    return seg_i;
}

/**
 * @brief 添加新的hash节，通过将节移动到文件末尾实现。
 * add a new hash section by moving it to the end of the file.
 * @param elfname 
 * @param content new section content
 * @param content_size new section content size
 * @return segment index {-1:error}
 */
int add_hash_segment(char *elfname, char *content, size_t content_size) {
    // get offset and size
    uint64_t addr, offset;
    size_t size;
    int seg_i, sec_i;
    get_dynamic_value_by_tag(elfname, DT_GNU_HASH, &addr);
    //get_dynamic_value_by_tag(elfname, DT_STRSZ, &size);
    VERBOSE("dynamic strtab addr: 0x%x, size: 0x%x\n", addr, size);

    // copy
    // fix error in expanding segment if addr != offset
    offset = get_section_offset(elfname, ".gnu.hash");
    seg_i = expand_segment(elfname, 0, 0, content, content_size);

    // set phdr
    VERBOSE("set phdr\n");
    addr = get_segment_vaddr(elfname, seg_i);
    offset = get_segment_offset(elfname, seg_i);
    size = get_segment_memsz(elfname, seg_i);
    set_dynamic_value_by_tag(elfname, DT_GNU_HASH, &addr);
    //set_dynamic_value_by_tag(elfname, DT_STRSZ, &size);
    
    // set shdr
    VERBOSE("set shdr\n");
    sec_i = get_section_index(elfname, ".gnu.hash");
    set_section_off(elfname, sec_i, offset);
    set_section_addr(elfname, sec_i, addr);
    set_section_size(elfname, sec_i, size);
    return seg_i;
}
