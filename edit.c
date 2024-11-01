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
#include "parse.h"

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

enum DynsymLabel {
    D_VAL,          /* Integer value */
};

/**
 * @brief Set the segment information
 * 
 * @param elf_name elf file name
 * @param index readelf .segment row
 * @param value value to be edited
 * @param label readelf .segment column
 * @return error code {-1:error,0:sucess}
 */
static int set_segment_info(char *elf_name, int index, int value, enum SegmentLabel label) {
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
            case P_TYPE:
                phdr[index].p_type = value;
                break;
            
            case P_FLAGS:
                phdr[index].p_flags = value;
                break;

            case P_OFFSET:
                phdr[index].p_offset = value;
                break;

            case P_VADDR:
                phdr[index].p_vaddr = value;
                break;

            case P_FILESZ:
                phdr[index].p_filesz = value;
                break;

            case P_MEMSZ:
                phdr[index].p_memsz = value;
                break;

            case P_ALIGN:
                phdr[index].p_align = value;
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
            case P_TYPE:
                phdr[index].p_type = value;
                break;
            
            case P_FLAGS:
                phdr[index].p_flags = value;
                break;

            case P_OFFSET:
                phdr[index].p_offset = value;
                break;

            case P_VADDR:
                phdr[index].p_vaddr = value;
                break;

            case P_FILESZ:
                phdr[index].p_filesz = value;
                break;

            case P_MEMSZ:
                phdr[index].p_memsz = value;
                break;

            case P_ALIGN:
                phdr[index].p_align = value;
                break;
        
            default:
                break;
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
};

/**
 * @brief Set the segment type
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_type(char *elf_name, int index, int value) {
    return set_segment_info(elf_name, index, value, P_TYPE);
}

/**
 * @brief Set the segment flags
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_flags(char *elf_name, int index, int value) {
    return set_segment_info(elf_name, index, value, P_FLAGS);
}

/**
 * @brief Set the segment offset
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_offset(char *elf_name, int index, int value) {
    return set_segment_info(elf_name, index, value, P_OFFSET);
}

/**
 * @brief Set the segment vaddr
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_vaddr(char *elf_name, int index, int value) {
    return set_segment_info(elf_name, index, value, P_VADDR);
}

/**
 * @brief Set the segment paddr
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_paddr(char *elf_name, int index, int value) {
    return set_segment_info(elf_name, index, value, P_PADDR);
}

/**
 * @brief Set the segment filesz
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_filesz(char *elf_name, int index, int value) {
    return set_segment_info(elf_name, index, value, P_FILESZ);
}

/**
 * @brief Set the segment memsz
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_memsz(char *elf_name, int index, int value) {
    return set_segment_info(elf_name, index, value, P_MEMSZ);
}

/**
 * @brief Set the segment align
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_align(char *elf_name, int index, int value) {
    return set_segment_info(elf_name, index, value, P_ALIGN);
}

/**
 * @brief Set the dynsym information
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param label readelf .dynsym column
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_info(char *elf_name, int index, int value, enum DynsymLabel label) {
    MODE = get_elf_class(elf_name);
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *tmp_sec_name;

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
        Elf32_Shdr *shdr;
        Elf32_Shdr shstrtab;
        Elf32_Sym *sym;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(".dynsym", tmp_sec_name)) {
                int size = 0;
                /* security check start*/
                if (shdr[i].sh_entsize != 0)
                    size = shdr[i].sh_size / shdr[i].sh_entsize;
                else
                    return -1;
                if (index >= size)
                    return -1;
                /* security check end*/
                sym = (Elf32_Sym *)(elf_map + shdr[i].sh_offset);
                switch (label)
                {
                case D_VAL:
                    printf("%x->%x\n", sym[index].st_value, value);
                    sym[index].st_value = value;
                    break;
                default:
                    break;
                }
                break;
            }
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;
        Elf64_Sym *sym;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(".dynsym", tmp_sec_name)) {
                int size = 0;
                /* security check start*/
                if (shdr[i].sh_entsize != 0)
                    size = shdr[i].sh_size / shdr[i].sh_entsize;
                else
                    return -1;
                if (index >= size)
                    return -1;
                /* security check end*/
                sym = (Elf64_Sym *)(elf_map + shdr[i].sh_offset);
                switch (label)
                {
                case D_VAL:
                    printf("%x->%x\n", sym[index].st_value, value);
                    sym[index].st_value = value;
                    break;
                default:
                    break;
                }
                break;
            }
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
};

/**
 * @brief Set the dynsym value object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_value(char *elf_name, int index, int value) {
    return set_dynsym_info(elf_name, index, value, D_VAL);
}

/**
 * @brief entry function
 * 
 * @param elf elf file name
 * @param po selection
 * @return error code {-1:error,0:sucess} 
 */
int edit(char *elf, parser_opt_t *po, int row, int column, int value) {
    int error_code = 0;

    /* edit ELF header information */
    if (!get_option(po, HEADERS) || !get_option(po, ALL)) {
        // TODO:
        ;
    }

    /* edit section informtion */
    if (!get_option(po, SECTIONS) || !get_option(po, ALL)) {
        // TODO:
        ;
    }
    
    /* edit segment information */
    if (!get_option(po, SEGMENTS) || !get_option(po, ALL)) {
        switch (column)
        {
            case 0:
                error_code = set_segment_type(elf, row, value);
                break;

            case 1:
                error_code = set_segment_offset(elf, row, value);
                break;

            case 2:
                error_code = set_segment_vaddr(elf, row, value);
                break;

            case 3:
                error_code = set_segment_paddr(elf, row, value);
                break;

            case 4:
                error_code = set_segment_filesz(elf, row, value);
                break;

            case 5:
                error_code = set_segment_memsz(elf, row, value);
                break;

            case 6:
                error_code = set_segment_flags(elf, row, value);
                break;

            case 7:
                error_code = set_segment_align(elf, row, value);
                break;
            
            default:
                break;
        }
    }

    /* edit .dynsym informtion */
    if (!get_option(po, DYNSYM) || !get_option(po, ALL)) {
        // TODO:
        ;
    }

    return error_code;
}