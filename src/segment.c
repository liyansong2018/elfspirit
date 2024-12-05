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
        // 计算地址的最大值和最小值
        // calculate the maximum and minimum values of the virtual address
        for (int i = 1; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                if (phdr[i].p_vaddr <= phdr[0].p_vaddr)
                    if (phdr[i].p_vaddr + phdr[i].p_memsz >= phdr[0].p_vaddr + phdr[0].p_memsz) {
                        index = i;
                        break;
                    }     
            }
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
        Elf64_Phdr *phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        // 计算地址的最大值和最小值
        // calculate the maximum and minimum values of the virtual address
        for (int i = 1; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                if (phdr[i].p_vaddr <= phdr[0].p_vaddr)
                    if (phdr[i].p_vaddr + phdr[i].p_memsz >= phdr[0].p_vaddr + phdr[0].p_memsz) {
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
        phdr[ehdr->e_phnum - 1].p_type = PT_LOAD;
        phdr[ehdr->e_phnum - 1].p_offset = ehdr->e_phoff;
        phdr[ehdr->e_phnum - 1].p_vaddr = phdr[0].p_vaddr;
        phdr[ehdr->e_phnum - 1].p_paddr = phdr[0].p_vaddr;
        phdr[ehdr->e_phnum - 1].p_filesz = phdr_size;
        phdr[ehdr->e_phnum - 1].p_memsz = phdr_size;
        phdr[ehdr->e_phnum - 1].p_flags = 4;
        phdr[ehdr->e_phnum - 1].p_align = 4096; 
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
        phdr[ehdr->e_phnum - 1].p_type = PT_LOAD;
        phdr[ehdr->e_phnum - 1].p_offset = ehdr->e_phoff;
        phdr[ehdr->e_phnum - 1].p_vaddr = phdr[0].p_vaddr;
        phdr[ehdr->e_phnum - 1].p_paddr = phdr[0].p_vaddr;
        phdr[ehdr->e_phnum - 1].p_filesz = phdr_size;
        phdr[ehdr->e_phnum - 1].p_memsz = phdr_size;
        phdr[ehdr->e_phnum - 1].p_flags = 4;
        phdr[ehdr->e_phnum - 1].p_align = 4096; 
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
int add_hpdr(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    uint64_t tmpsize;
    int index;

    index = get_phdr_load(elf_name);
    VERBOSE("get the phdr load index: %d\n", index);

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
 * @param start segment size
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

    // 如果程序头在ELF文件末尾处，直接增加一个段
    // if program header is at the end of elf
    add_hpdr(elf_name);
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
        index = ehdr->e_phnum - 1;
    }

    VERBOSE("add segment successfully: [%d]\n", index);
    close(fd);
    munmap(mapped, st.st_size);
    return index;
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