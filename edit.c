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

enum HeaderLabel {
    E_IDENT,        /* Magic number and other info */
    E_TYPE,         /* Object file type */
    E_MACHINE,      /* Architecture */
    E_VERSION,      /* Object file version */
    E_ENTRY,        /* Entry point virtual address */
    E_PHOFF,        /* Program header table file offset */
    E_SHOFF,        /* Section header table file offset */
    E_FLAGS,        /* Processor-specific flags */
    E_EHSIZE,       /* ELF header size in bytes */
    E_PHENTSIZE,    /* Program header table entry size */
    E_PHNUM,        /* Program header table entry count */
    E_SHENTSIZE,    /* Section header table entry size */
    E_SHNUM,        /* Section header table entry count */
    E_SHSTRNDX,     /* Section header table entry count */
};

enum SectionLabel {
    S_NAME,	        /* Section name (string tbl index) */
    S_TYPE,         /* Section type */
    S_FLAGS,        /* Section flags */
    S_ADDR,		    /* Section virtual addr at execution */
    S_OFF,		    /* Section file offset */
    S_SIZE,		    /* Section size in bytes */
    S_LINK,		    /* Link to another section */
    S_INFO,		    /* Additional section information */
    S_ALIGN,        /* Section alignment */
    S_ENTSIZE,	    /* Entry size if section holds table */
};

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

enum SymbolLabel {
    ST_NAME,        /* Symbol name (string tbl index) */
    ST_VALUE,       /* Symbol value */
    ST_SIZE,        /* Symbol size */
    ST_INFO,        /* Symbol type and binding */
    ST_TYPE,
    ST_BIND,
    ST_OTHER,       /* Symbol visibility */
    ST_SHNDX,       /* Section index */
};

/**
 * @brief Set the elf header information object
 * 
 * @param elf_name elf file name
 * @param value 
 * @param label readelf elf header column
 * @return error code {-1:error,0:sucess}
 */
static int set_header(char *elf_name, int value, enum HeaderLabel label) {
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
        ehdr = (Elf32_Ehdr *)elf_map;

        switch (label)
        {
            case E_IDENT:
                break;

            case E_TYPE:
                printf("%x->%x\n", ehdr->e_type, value);
                ehdr->e_type = value;
                break;

            case E_MACHINE:
                printf("%x->%x\n", ehdr->e_machine, value);
                ehdr->e_machine = value;
                break;
            
            case E_VERSION:
                printf("%x->%x\n", ehdr->e_version, value);
                ehdr->e_version = value;
                break;

            case E_ENTRY:
                printf("%x->%x\n", ehdr->e_entry, value);
                ehdr->e_entry= value;
                break;

            case E_PHOFF:
                printf("%x->%x\n", ehdr->e_phoff, value);
                ehdr->e_phoff = value;
                break;

            case E_SHOFF:
                printf("%x->%x\n", ehdr->e_shoff, value);
                ehdr->e_shoff = value;
                break;

            case E_FLAGS:
                printf("%x->%x\n", ehdr->e_flags, value);
                ehdr->e_flags = value;
                break;

            case E_EHSIZE:
                printf("%x->%x\n", ehdr->e_ehsize, value);
                ehdr->e_ehsize = value;
                break;

            case E_PHENTSIZE:
                printf("%x->%x\n", ehdr->e_phentsize, value);
                ehdr->e_phentsize = value;
                break;

            case E_PHNUM:
                printf("%x->%x\n", ehdr->e_phnum, value);
                ehdr->e_phnum = value;
                break;

            case E_SHENTSIZE:
                printf("%x->%x\n", ehdr->e_shentsize, value);
                ehdr->e_shentsize = value;
                break;

            case E_SHNUM:
                printf("%x->%x\n", ehdr->e_shnum, value);
                ehdr->e_shnum = value;
                break;

            case E_SHSTRNDX:
                printf("%x->%x\n", ehdr->e_shstrndx, value);
                ehdr->e_shstrndx = value;
                break;
            
            default:
                break;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        ehdr = (Elf64_Ehdr *)elf_map;

        switch (label)
        {
            case E_IDENT:
                break;

            case E_TYPE:
                printf("%x->%x\n", ehdr->e_type, value);
                ehdr->e_type = value;
                break;

            case E_MACHINE:
                printf("%x->%x\n", ehdr->e_machine, value);
                ehdr->e_machine = value;
                break;
            
            case E_VERSION:
                printf("%x->%x\n", ehdr->e_version, value);
                ehdr->e_version = value;
                break;

            case E_ENTRY:
                printf("%x->%x\n", ehdr->e_entry, value);
                ehdr->e_entry= value;
                break;

            case E_PHOFF:
                printf("%x->%x\n", ehdr->e_phoff, value);
                ehdr->e_phoff = value;
                break;

            case E_SHOFF:
                printf("%x->%x\n", ehdr->e_shoff, value);
                ehdr->e_shoff = value;
                break;

            case E_FLAGS:
                printf("%x->%x\n", ehdr->e_flags, value);
                ehdr->e_flags = value;
                break;

            case E_EHSIZE:
                printf("%x->%x\n", ehdr->e_ehsize, value);
                ehdr->e_ehsize = value;
                break;

            case E_PHENTSIZE:
                printf("%x->%x\n", ehdr->e_phentsize, value);
                ehdr->e_phentsize = value;
                break;

            case E_PHNUM:
                printf("%x->%x\n", ehdr->e_phnum, value);
                ehdr->e_phnum = value;
                break;

            case E_SHENTSIZE:
                printf("%x->%x\n", ehdr->e_shentsize, value);
                ehdr->e_shentsize = value;
                break;

            case E_SHNUM:
                printf("%x->%x\n", ehdr->e_shnum, value);
                ehdr->e_shnum = value;
                break;

            case E_SHSTRNDX:
                printf("%x->%x\n", ehdr->e_shstrndx, value);
                ehdr->e_shstrndx = value;
                break;
            
            default:
                break;
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

/**
 * @brief Set the section name
 * 
 * @param elf_name elf file name
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_header_type(char *elf_name, int value) {
    return set_header(elf_name, value, E_TYPE);
}

int set_header_machine(char *elf_name, int value) {
    return set_header(elf_name, value, E_MACHINE);
}

int set_header_version(char *elf_name, int value) {
    return set_header(elf_name, value, E_VERSION);
}

int set_header_entry(char *elf_name, int value) {
    return set_header(elf_name, value, E_ENTRY);
}

int set_header_phoff(char *elf_name, int value) {
    return set_header(elf_name, value, E_PHOFF);
}

int set_header_shoff(char *elf_name, int value) {
    return set_header(elf_name, value, E_SHOFF);
}

int set_header_flags(char *elf_name, int value) {
    return set_header(elf_name, value, E_FLAGS);
}

int set_header_ehsize(char *elf_name, int value) {
    return set_header(elf_name, value, E_EHSIZE);
}

int set_header_phentsize(char *elf_name, int value) {
    return set_header(elf_name, value, E_PHENTSIZE);
}

int set_header_phnum(char *elf_name, int value) {
    return set_header(elf_name, value, E_PHNUM);
}

int set_header_shentsize(char *elf_name, int value) {
    return set_header(elf_name, value, E_SHENTSIZE);
}

int set_header_shnum(char *elf_name, int value) {
    return set_header(elf_name, value, E_SHNUM);
}

int set_header_shstrndx(char *elf_name, int value) {
    return set_header(elf_name, value, E_SHSTRNDX);
}

/**
 * @brief Set the section information object
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @param label readelf section column
 * @return error code {-1:error,0:sucess}
 */
static int set_section(char *elf_name, int index, int value, enum SectionLabel label) {
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

    /* rwx -> xrw*/
    int section_flags = ((value & 1) << 2) | ((value & 2) >> 1) | ((value & 4) >> 1);
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];

        switch (label)
        {
            case S_NAME:
                printf("%x->%x\n", shdr[index].sh_name, value);
                shdr[index].sh_name = value;
                break;

            case S_TYPE:
                printf("%x->%x\n", shdr[index].sh_type, value);
                shdr[index].sh_type = value;
                break;

            case S_FLAGS:
                printf("%x->%x\n", shdr[index].sh_flags, value);
                shdr[index].sh_flags = section_flags;
                break;
            
            case S_ADDR:
                printf("%x->%x\n", shdr[index].sh_addr, value);
                shdr[index].sh_addr = value;
                break;

            case S_OFF:
                printf("%x->%x\n", shdr[index].sh_offset, value);
                shdr[index].sh_offset = value;
                break;

            case S_SIZE:
                printf("%x->%x\n", shdr[index].sh_size, value);
                shdr[index].sh_size = value;
                break;

            case S_LINK:
                printf("%x->%x\n", shdr[index].sh_link, value);
                shdr[index].sh_link = value;
                break;

            case S_INFO:
                printf("%x->%x\n", shdr[index].sh_info, value);
                shdr[index].sh_info = value;
                break;

            case S_ALIGN:
                printf("%x->%x\n", shdr[index].sh_addralign, value);
                shdr[index].sh_addralign = value;
                break;

            case S_ENTSIZE:
                printf("%x->%x\n", shdr[index].sh_entsize, value);
                shdr[index].sh_entsize = value;
                break;
            
            default:
                break;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];

        switch (label)
        {
            case S_NAME:
                printf("%x->%x\n", shdr[index].sh_name, value);
                shdr[index].sh_name = value;
                break;

            case S_TYPE:
                printf("%x->%x\n", shdr[index].sh_type, value);
                shdr[index].sh_type = value;
                break;

            case S_FLAGS:
                printf("%x->%x\n", shdr[index].sh_flags, value);
                shdr[index].sh_flags = section_flags;
                break;
            
            case S_ADDR:
                printf("%x->%x\n", shdr[index].sh_addr, value);
                shdr[index].sh_addr = value;
                break;

            case S_OFF:
                printf("%x->%x\n", shdr[index].sh_offset, value);
                shdr[index].sh_offset = value;
                break;

            case S_SIZE:
                printf("%x->%x\n", shdr[index].sh_size, value);
                shdr[index].sh_size = value;
                break;

            case S_LINK:
                printf("%x->%x\n", shdr[index].sh_link, value);
                shdr[index].sh_link = value;
                break;

            case S_INFO:
                printf("%x->%x\n", shdr[index].sh_info, value);
                shdr[index].sh_info = value;
                break;

            case S_ALIGN:
                printf("%x->%x\n", shdr[index].sh_addralign, value);
                shdr[index].sh_addralign = value;
                break;

            case S_ENTSIZE:
                printf("%x->%x\n", shdr[index].sh_entsize, value);
                shdr[index].sh_entsize = value;
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
 * @brief Set the section name
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_section_name(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_NAME);
}

int set_section_type(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_TYPE);
}

int set_section_flags(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_FLAGS);
}

int set_section_addr(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_ADDR);
}

int set_section_off(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_OFF);
}

int set_section_size(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_SIZE);
}

int set_section_link(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_LINK);
}

int set_section_info(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_INFO);
}

int set_section_align(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_ALIGN);
}

int set_section_entsize(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_ENTSIZE);
}

/**
 * @brief Set the segment information
 * 
 * @param elf_name elf file name
 * @param index readelf .segment row
 * @param value value to be edited
 * @param label readelf .segment column
 * @return error code {-1:error,0:sucess}
 */
static int set_segment(char *elf_name, int index, int value, enum SegmentLabel label) {
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
                printf("%x->%x\n", phdr[index].p_type, value);
                phdr[index].p_type = value;
                break;
            
            case P_FLAGS:
                printf("%x->%x\n", phdr[index].p_flags, value);
                phdr[index].p_flags = value;
                break;

            case P_OFFSET:
                printf("%x->%x\n", phdr[index].p_offset, value);
                phdr[index].p_offset = value;
                break;

            case P_VADDR:
                printf("%x->%x\n", phdr[index].p_vaddr, value);
                phdr[index].p_vaddr = value;
                break;

            case P_FILESZ:
                printf("%x->%x\n", phdr[index].p_filesz, value);
                phdr[index].p_filesz = value;
                break;

            case P_MEMSZ:
                printf("%x->%x\n", phdr[index].p_memsz, value);
                phdr[index].p_memsz = value;
                break;

            case P_ALIGN:
                printf("%x->%x\n", phdr[index].p_align, value);
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
                printf("%x->%x\n", phdr[index].p_type, value);
                phdr[index].p_type = value;
                break;
            
            case P_FLAGS:
                printf("%x->%x\n", phdr[index].p_flags, value);
                phdr[index].p_flags = value;
                break;

            case P_OFFSET:
                printf("%x->%x\n", phdr[index].p_offset, value);
                phdr[index].p_offset = value;
                break;

            case P_VADDR:
                printf("%x->%x\n", phdr[index].p_vaddr, value);
                phdr[index].p_vaddr = value;
                break;

            case P_FILESZ:
                printf("%x->%x\n", phdr[index].p_filesz, value);
                phdr[index].p_filesz = value;
                break;

            case P_MEMSZ:
                printf("%x->%x\n", phdr[index].p_memsz, value);
                phdr[index].p_memsz = value;
                break;

            case P_ALIGN:
                printf("%x->%x\n", phdr[index].p_align, value);
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
    return set_segment(elf_name, index, value, P_TYPE);
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
    return set_segment(elf_name, index, value, P_FLAGS);
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
    return set_segment(elf_name, index, value, P_OFFSET);
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
    return set_segment(elf_name, index, value, P_VADDR);
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
    return set_segment(elf_name, index, value, P_PADDR);
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
    return set_segment(elf_name, index, value, P_FILESZ);
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
    return set_segment(elf_name, index, value, P_MEMSZ);
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
    return set_segment(elf_name, index, value, P_ALIGN);
}

/**
 * @brief Set the symbol information
 * 
 * @param elf_name elf file name
 * @param index readelf symbol row
 * @param value value to be edited
 * @param label readelf symbol column
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_symbol_info(char *elf_name, int index, int value, enum SymbolLabel label, char *section_name) {
    MODE = get_elf_class(elf_name);
    int fd;
    struct stat st;
    int type;
    int bind;
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
            if (!strcmp(section_name, tmp_sec_name)) {
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
                    case ST_NAME:
                        printf("%x->%x\n", sym[index].st_name, value);
                        sym[index].st_name = value;
                        break;
                    
                    case ST_VALUE:
                        printf("%x->%x\n", sym[index].st_value, value);
                        sym[index].st_value = value;
                        break;
                    
                    case ST_SIZE:
                        printf("%x->%x\n", sym[index].st_size, value);
                        sym[index].st_size = value;
                        break;

                    case ST_TYPE:
                        type = ELF32_ST_TYPE(sym[index].st_info);
                        bind = ELF32_ST_BIND(sym[index].st_info);
                        printf("%x->%x\n", type, value);
                        sym[index].st_info = ELF32_ST_INFO(bind, value);
                        break;

                    case ST_BIND:
                        type = ELF32_ST_TYPE(sym[index].st_info);
                        bind = ELF32_ST_BIND(sym[index].st_info);
                        printf("%x->%x\n", bind, value);
                        sym[index].st_info = ELF32_ST_INFO(value, type);
                        break;

                    case ST_OTHER:
                        printf("%x->%x\n", sym[index].st_other, value);
                        sym[index].st_other = value;
                        break;

                    case ST_SHNDX:
                        printf("%x->%x\n", sym[index].st_shndx, value);
                        sym[index].st_shndx = value;
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
            if (!strcmp(section_name, tmp_sec_name)) {
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
                    case ST_NAME:
                        printf("%x->%x\n", sym[index].st_name, value);
                        sym[index].st_name = value;
                        break;
                    
                    case ST_VALUE:
                        printf("%x->%x\n", sym[index].st_value, value);
                        sym[index].st_value = value;
                        break;
                    
                    case ST_SIZE:
                        printf("%x->%x\n", sym[index].st_size, value);
                        sym[index].st_size = value;
                        break;

                    case ST_TYPE:
                        type = ELF64_ST_TYPE(sym[index].st_info);
                        bind = ELF64_ST_BIND(sym[index].st_info);
                        printf("%x->%x\n", type, value);
                        sym[index].st_info = ELF64_ST_INFO(bind, value);
                        break;

                    case ST_BIND:
                        type = ELF64_ST_TYPE(sym[index].st_info);
                        bind = ELF64_ST_BIND(sym[index].st_info);
                        printf("%x->%x\n", bind, value);
                        sym[index].st_info = ELF64_ST_INFO(value, type);
                        break;

                    case ST_OTHER:
                        printf("%x->%x\n", sym[index].st_other, value);
                        sym[index].st_other = value;
                        break;

                    case ST_SHNDX:
                        printf("%x->%x\n", sym[index].st_shndx, value);
                        sym[index].st_shndx = value;
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
 * @brief Set the dynsym name object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_name(char *elf_name, int index, int value, char *section_name) {
    return set_symbol_info(elf_name, index, value, ST_NAME, section_name);
}

/**
 * @brief Set the dynsym value object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_value(char *elf_name, int index, int value, char *section_name) {
    return set_symbol_info(elf_name, index, value, ST_VALUE, section_name);
}

/**
 * @brief Set the dynsym size object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_size(char *elf_name, int index, int value, char *section_name) {
    return set_symbol_info(elf_name, index, value, ST_SIZE, section_name);
}

/**
 * @brief Set the dynsym type object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_type(char *elf_name, int index, int value, char *section_name) {
    return set_symbol_info(elf_name, index, value, ST_TYPE, section_name);
}

/**
 * @brief Set the dynsym bind object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_bind(char *elf_name, int index, int value, char *section_name) {
    return set_symbol_info(elf_name, index, value, ST_BIND, section_name);
}

/**
 * @brief Set the dynsym other object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_other(char *elf_name, int index, int value, char *section_name) {
    return set_symbol_info(elf_name, index, value, ST_OTHER, section_name);
}

/**
 * @brief Set the dynsym shndx object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_shndx(char *elf_name, int index, int value, char *section_name) {
    return set_symbol_info(elf_name, index, value, ST_SHNDX, section_name);
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
    if (!get_option(po, HEADERS)) {
        switch (row)
        {
            case 0:
                error_code = set_header_type(elf, value);
                break;

            case 1:
                error_code = set_header_machine(elf, value);
                break;

            case 2:
                error_code = set_header_version(elf, value);
                break;

            case 3:
                error_code = set_header_entry(elf, value);
                break;

            case 4:
                error_code = set_header_phoff(elf, value);
                break;

            case 5:
                error_code = set_header_shoff(elf, value);
                break;

            case 6:
                error_code = set_header_flags(elf, value);
                break;

            case 7:
                error_code = set_header_ehsize(elf, value);
                break;

            case 8:
                error_code = set_header_phentsize(elf, value);
                break;

            case 9:
                error_code = set_header_phnum(elf, value);
                break;

            case 10:
                error_code = set_header_shentsize(elf, value);
                break;
            
            case 11:
                error_code = set_header_shnum(elf, value);
                break;
            
            case 12:
                error_code = set_header_shstrndx(elf, value);
                break;
            
            default:
                break;
        }
    }

    /* edit section informtion */
    if (!get_option(po, SECTIONS)) {
        switch (column)
        {
            case 0:
                error_code = set_section_name(elf, row, value);
                break;

            case 1:
                error_code = set_section_type(elf, row, value);
                break;

            case 2:
                error_code = set_section_addr(elf, row, value);
                break;

            case 3:
                error_code = set_section_off(elf, row, value);
                break;

            case 4:
                error_code = set_section_size(elf, row, value);
                break;

            case 5:
                error_code = set_section_entsize(elf, row, value);
                break;

            case 6:
                error_code = set_section_flags(elf, row, value);
                break;

            case 7:
                error_code = set_section_link(elf, row, value);
                break;

            case 8:
                error_code = set_section_info(elf, row, value);
                break;

            case 9:
                error_code = set_section_align(elf, row, value);
                break;
            
            default:
                break;
        }
    }
    
    /* edit segment information */
    if (!get_option(po, SEGMENTS)) {
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
    if (!get_option(po, DYNSYM)) {
        switch (column)
        {
            case 0:
                error_code = set_dynsym_value(elf, row, value, ".dynsym");
                break;

            case 1:
                error_code = set_dynsym_size(elf, row, value, ".dynsym");
                break;

            case 2:
                error_code = set_dynsym_type(elf, row, value, ".dynsym");
                break;

            case 3:
                error_code = set_dynsym_bind(elf, row, value, ".dynsym");
                break;

            case 4:
                error_code = set_dynsym_other(elf, row, value, ".dynsym");
                break;

            case 5:
                error_code = set_dynsym_shndx(elf, row, value, ".dynsym");
                break;

            case 6:
                error_code = set_dynsym_name(elf, row, value, ".dynsym");
                break;
            
            default:
                break;
        }
    }

    /* edit .symtab informtion */
    if (!get_option(po, SYMTAB)) {
        switch (column)
        {
            case 0:
                error_code = set_dynsym_value(elf, row, value, ".symtab");
                break;

            case 1:
                error_code = set_dynsym_size(elf, row, value, ".symtab");
                break;

            case 2:
                error_code = set_dynsym_type(elf, row, value, ".symtab");
                break;

            case 3:
                error_code = set_dynsym_bind(elf, row, value, ".symtab");
                break;

            case 4:
                error_code = set_dynsym_other(elf, row, value, ".symtab");
                break;

            case 5:
                error_code = set_dynsym_shndx(elf, row, value, ".symtab");
                break;

            case 6:
                error_code = set_dynsym_name(elf, row, value, ".symtab");
                break;
            
            default:
                break;
        }
    }

    return error_code;
}