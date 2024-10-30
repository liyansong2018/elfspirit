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

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include "common.h"

enum SegmentLabel {
    P_TYPE,		    /* Segment type */
    P_FLAGS,	    /* Segment flags */
    P_OFFSET,	    /* Segment file offset */
    P_VADDR,	    /* Segment virtual address */
    P_PADDR,	    /* Segment physical address */
    P_FILESZ,	    /* Segment size in file */
    P_MEMSZ,	    /* Segment size in memory */
    P_ALIGN,	    /* Segment alignment */
};

void set_segment_info(char *elf_name, int index, int value, enum SegmentLabel label) {
    MODE = get_elf_class(elf_name);
    int fd;
    struct stat st;
    uint8_t *elf_map;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;

        ehdr = (Elf32_Ehdr *)elf_map;
        phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];

        switch (label)
        {
        case P_FLAGS:
            phdr[index].p_flags = value;
            break;
        
        default:
            break;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;

        ehdr = (Elf64_Ehdr *)elf_map;
        phdr = (Elf64_Phdr *)&elf_map[ehdr->e_phoff];

        switch (label)
        {
        case P_FLAGS:
            phdr[index].p_flags = value;
            break;
        
        default:
            break;
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
};

void set_segment_flags(char *elf_name, int index, int value) {
    set_segment_info(elf_name, index, value, P_FLAGS);
}