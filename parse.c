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
#include "parse.h"

#define PRINT_HEADER_EXP(Nr, key, value, explain) printf ("     [%2d] %-20s %10p (%s)\n", Nr, key, value, explain)
#define PRINT_HEADER(Nr, key, value) printf ("     [%2d] %-20s %10p\n", Nr, key, value)
/* print section header table */
#define PRINT_SECTION(Nr, name, type, addr, off, size, es, flg, lk, inf, al) \
    printf("     [%2d] %-15s %-15s %08x %06x %06x %02x %4s %3u %3u %3u\n", \
    Nr, name, type, addr, off, size, es, flg, lk, inf, al)
#define PRINT_SECTION_TITLE(Nr, name, type, addr, off, size, es, flg, lk, inf, al) \
    printf("     [%2s] %-15s %-15s %8s %6s %6s %2s %4s %3s %3s %3s\n", \
    Nr, name, type, addr, off, size, es, flg, lk, inf, al)

/* print program header table*/
#define PRINT_PROGRAM(Nr, type, offset, virtaddr, physaddr, filesiz, memsiz, flg, align) \
    printf("     [%2d] %-15s %08x %08x %08x %08x %08x %-4s %5u\n", \
    Nr, type, offset, virtaddr, physaddr, filesiz, memsiz, flg, align)
#define PRINT_PROGRAM_TITLE(Nr, type, offset, virtaddr, physaddr, filesiz, memsiz, flg, align) \
    printf("     [%2s] %-15s %8s %8s %8s %8s %8s %-4s %5s\n", \
    Nr, type, offset, virtaddr, physaddr, filesiz, memsiz, flg, align)

/* print dynamic symbol table*/
#define PRINT_DYNSYM(Nr, value, size, type, bind, vis, ndx, name) \
    printf("     [%2d] %08x %4d %-8s %-8s %-8s %4d %-20s\n", \
    Nr, value, size, type, bind, vis, ndx, name)
#define PRINT_DYNSYM_TITLE(Nr, value, size, type, bind, vis, ndx, name) \
    printf("     [%2s] %8s %4s %-8s %-8s %-8s %4s %-20s\n", \
    Nr, value, size, type, bind, vis, ndx, name)

/* print dynamic table*/
#define PRINT_DYN(tag, type, value) \
    printf("     %08x   %-15s   %-30s\n", \
    tag, type, value);
#define PRINT_DYN_TITLE(tag, type, value) \
    printf("     %-10s   %-15s   %-30s\n", \
    tag, type, value);

int flag2str(int flag, char *flag_str) {
    if (flag & 0x1)
        flag_str[2] = 'E';
    if (flag >> 1 & 0x1)
        flag_str[1] = 'W';
    if (flag >> 2 & 0x1)
        flag_str[0] = 'R';
    
    return 0;
}

int flag2str_sh(int flag, char *flag_str) {
    if (flag & 0x1)
        flag_str[2] = 'W';
    if (flag >> 1 & 0x1)
        flag_str[1] = 'A';
    if (flag >> 2 & 0x1)
        flag_str[0] = 'E';
    
    return 0;
}

/**
 * @description: Judge whether the memory address is legal
 * @param {uint32_t} addr
 * @param {uint32_t} start
 * @param {uint32_t} end
 * @return {*}
 */
int validated_offset(uint32_t addr, uint32_t start, uint32_t end){
    return addr <= end && addr >= start? 0:-1;
}

/**
 * @description: Judge whether the option is true
 * @param {parser_opt_t} po
 * @param {PARSE_OPT_T} option
 * @return {*}
 */
int get_option(parser_opt_t *po, PARSE_OPT_T option){
    int i;
    for (i = 0; i < po->index; i++) {
        if (po->options[i] == option) {
            return 0;
        }
    }

    return -1;
}

static void display_header32(handle_t32 *);
static void display_header64(handle_t64 *);
static void display_section32(handle_t32 *);
static void display_section64(handle_t64 *);
static void display_segment32(handle_t32 *);
static void display_segment64(handle_t64 *);
static void display_dynsym32(handle_t32 *, char *section_name, char *str_tab);
static void display_dynsym64(handle_t64 *, char *section_name, char *str_tab);
static void display_dyninfo32(handle_t32 *);
static void display_dyninfo64(handle_t64 *);

int parse(char *elf, parser_opt_t *po) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    int count;
    char *tmp;
    char *name;
    char flag[4];

    MODE = get_elf_class(elf);
    if (MODE == -1) {
        return -1;
    }

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
        handle_t32 h;
        h.mem = elf_map;
        h.ehdr = (Elf32_Ehdr *)h.mem;
        h.shdr = (Elf32_Shdr *)&h.mem[h.ehdr->e_shoff];
        h.phdr = (Elf32_Phdr *)&h.mem[h.ehdr->e_phoff];
        h.shstrtab = (Elf32_Shdr *)&h.shdr[h.ehdr->e_shstrndx];
        h.size = st.st_size;

        /* ELF Header Information */
        if (!get_option(po, HEADERS) || !get_option(po, ALL))    
            display_header32(&h);
        
        /* Section Information */
        if (!get_option(po, SECTIONS) || !get_option(po, ALL))
            display_section32(&h);

        /* Segmentation Information */
        if (!get_option(po, SEGMENTS) || !get_option(po, ALL))
            display_segment32(&h);

        /* .dynsym information */
        if (!get_option(po, DYNSYM) || !get_option(po, ALL)){
            display_dynsym32(&h, ".dynsym", ".dynstr");
        }

        /* .symtab information */
        if (!get_option(po, SYMTAB) || !get_option(po, ALL)){
            display_dynsym32(&h, ".symtab", ".strtab");
        }

        /* Dynamic Infomation */
        if (!get_option(po, LINK) || !get_option(po, ALL))
            display_dyninfo32(&h);           
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        handle_t64 h;
        h.mem = elf_map;
        h.ehdr = (Elf64_Ehdr *)h.mem;
        h.shdr = (Elf64_Shdr *)&h.mem[h.ehdr->e_shoff];
        h.phdr = (Elf64_Phdr *)&h.mem[h.ehdr->e_phoff];
        h.shstrtab = (Elf64_Shdr *)&h.shdr[h.ehdr->e_shstrndx];
        h.size = st.st_size;

        /* ELF Header Information */
        if (!get_option(po, HEADERS) || !get_option(po, ALL)) 
            display_header64(&h);

        /* Section Information */
        if (!get_option(po, SECTIONS) || !get_option(po, ALL))
            display_section64(&h);

        /* Segmentation Information */
        if (!get_option(po, SEGMENTS) || !get_option(po, ALL))
            display_segment64(&h);

        /* .dynsym information */
        if (!get_option(po, DYNSYM) || !get_option(po, ALL)){
            display_dynsym64(&h, ".dynsym", ".dynstr");
        }

        /* .symtab information */
        if (!get_option(po, SYMTAB) || !get_option(po, ALL)){
            display_dynsym64(&h, ".symtab", ".strtab");
        }

        /* Dynamic Infomation */
        if (!get_option(po, LINK) || !get_option(po, ALL))
            display_dyninfo64(&h);              
    }

    return 0;
}

/**
 * @description: ELF Header information
 * @param {handle_t32} h
 * @return {void}
 */
static void display_header32(handle_t32 *h) {
    char *tmp;
    int nr = 0;
    INFO("ELF32 Header\n");
    /* 16bit magic */
    printf("     0 ~ 15bit ----------------------------------------------\n");
    printf("     Magic: ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf(" %02x", h->ehdr->e_ident[i]);
    }    
    printf("\n");
    printf("            %3s %c  %c  %c  %c  %c  %c  %c  %c\n", "ELF", 'E', 'L', 'F', '|', '|', '|', '|', '|');
    printf("            %3s %10s  %c  %c  %c  %c\n", "   ", "32/64bit", '|', '|', '|', '|');
    printf("            %11s  %c  %c  %c\n", "little/big endian", '|', '|', '|');
    printf("            %20s  %c  %c\n", "os type", '|', '|');
    printf("            %23s  %c\n", "ABI version", '|');
    printf("            %26s\n", "byte index of padding bytes");
    printf("     16 ~ 63bit ---------------------------------------------\n");

    switch (h->ehdr->e_type) {
        case ET_NONE:
            tmp = "An unknown type";
            break;

        case ET_REL:
            tmp = "A relocatable file";
            break;

        case ET_EXEC:
            tmp = "An executable file";
            break;

        case ET_DYN:
            tmp = "A shared object";
            break;

        case ET_CORE:
            tmp = "A core file";
            break;
        
        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_type:", h->ehdr->e_type, tmp);

    switch (h->ehdr->e_type) {
        case EM_NONE:
            tmp = "An unknown machine";
            break;

        case EM_M32:
            tmp = "AT&T WE 32100";
            break;

        case EM_SPARC:
            tmp = "Sun Microsystems SPARC";
            break;

        case EM_386:
            tmp = "Intel 80386";
            break;

        case EM_68K:
            tmp = "Motorola 68000";
            break;
        
        case EM_88K:
            tmp = "Motorola 88000";
            break;

        case EM_860:
            tmp = "Intel 80860";
            break;

        case EM_MIPS:
            tmp = "MIPS RS3000 (big-endian only)";
            break;

        case EM_PARISC:
            tmp = "HP/PA";
            break;

        case EM_SPARC32PLUS:
            tmp = "SPARC with enhanced instruction set";
            break;
        
        case EM_PPC:
            tmp = "PowerPC";
            break;

        case EM_PPC64:
            tmp = "PowerPC 64-bit";
            break;

        case EM_S390:
            tmp = "IBM S/390";
            break;

        case EM_ARM:
            tmp = "Advanced RISC Machines";
            break;

        case EM_SH:
            tmp = "Renesas SuperH";
            break;
        
        case EM_SPARCV9:
            tmp = "SPARC v9 64-bit";
            break;

        case EM_IA_64:
            tmp = "Intel Itanium";
            break;

        case EM_X86_64:
            tmp = "AMD x86-64";
            break;

        case EM_VAX:
            tmp = "DEC Vax";
            break;
        
        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_machine:", h->ehdr->e_machine, tmp);

    switch (h->ehdr->e_version) {
        case EV_NONE:
            tmp = "Invalid version";
            break;

        case EV_CURRENT:
            tmp = "Current version";
            break;

        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_version:", h->ehdr->e_version, tmp);
    PRINT_HEADER_EXP(nr++, "e_entry:", h->ehdr->e_entry, "Entry point address");
    PRINT_HEADER_EXP(nr++, "e_phoff:", h->ehdr->e_phoff, "Start of program headers");
    PRINT_HEADER_EXP(nr++, "e_shoff:", h->ehdr->e_shoff, "Start of section headers");
    PRINT_HEADER(nr++, "e_flags:", h->ehdr->e_flags);
    PRINT_HEADER_EXP(nr++, "e_ehsize:", h->ehdr->e_ehsize, "Size of this header");
    PRINT_HEADER_EXP(nr++, "e_phentsize:", h->ehdr->e_phentsize, "Size of program headers");
    PRINT_HEADER_EXP(nr++, "e_phnum:", h->ehdr->e_phnum, "Number of program headers");
    PRINT_HEADER_EXP(nr++, "e_shentsize:", h->ehdr->e_shentsize, "Size of section headers");
    PRINT_HEADER_EXP(nr++, "e_shnum:", h->ehdr->e_shnum, "Number of section headers");
    PRINT_HEADER_EXP(nr++, "e_shstrndx:", h->ehdr->e_shstrndx, "Section header string table index");
}

static void display_header64(handle_t64 *h) {
    char *tmp;
    int nr = 0;
    INFO("ELF64 Header\n");
    /* 16bit magic */
    printf("     0 ~ 15bit ----------------------------------------------\n");
    printf("     Magic: ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf(" %02x", h->ehdr->e_ident[i]);
    }   
    printf("\n");
    printf("            %3s %c  %c  %c  %c  %c  %c  %c  %c\n", "ELF", 'E', 'L', 'F', '|', '|', '|', '|', '|');
    printf("            %3s %10s  %c  %c  %c  %c\n", "   ", "32/64bit", '|', '|', '|', '|');
    printf("            %11s  %c  %c  %c\n", "little/big endian", '|', '|', '|');
    printf("            %20s  %c  %c\n", "os type", '|', '|');
    printf("            %23s  %c\n", "ABI version", '|');
    printf("            %26s\n", "byte index of padding bytes");
    printf("     16 ~ 63bit ---------------------------------------------\n");

    switch (h->ehdr->e_type) {
        case ET_NONE:
            tmp = "An unknown type";
            break;

        case ET_REL:
            tmp = "A relocatable file";
            break;

        case ET_EXEC:
            tmp = "An executable file";
            break;

        case ET_DYN:
            tmp = "A shared object";
            break;

        case ET_CORE:
            tmp = "A core file";
            break;
        
        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_type:", h->ehdr->e_type, tmp);

    switch (h->ehdr->e_type) {
        case EM_NONE:
            tmp = "An unknown machine";
            break;

        case EM_M32:
            tmp = "AT&T WE 32100";
            break;

        case EM_SPARC:
            tmp = "Sun Microsystems SPARC";
            break;

        case EM_386:
            tmp = "Intel 80386";
            break;

        case EM_68K:
            tmp = "Motorola 68000";
            break;
        
        case EM_88K:
            tmp = "Motorola 88000";
            break;

        case EM_860:
            tmp = "Intel 80860";
            break;

        case EM_MIPS:
            tmp = "MIPS RS3000 (big-endian only)";
            break;

        case EM_PARISC:
            tmp = "HP/PA";
            break;

        case EM_SPARC32PLUS:
            tmp = "SPARC with enhanced instruction set";
            break;
        
        case EM_PPC:
            tmp = "PowerPC";
            break;

        case EM_PPC64:
            tmp = "PowerPC 64-bit";
            break;

        case EM_S390:
            tmp = "IBM S/390";
            break;

        case EM_ARM:
            tmp = "Advanced RISC Machines";
            break;

        case EM_SH:
            tmp = "Renesas SuperH";
            break;
        
        case EM_SPARCV9:
            tmp = "SPARC v9 64-bit";
            break;

        case EM_IA_64:
            tmp = "Intel Itanium";
            break;

        case EM_X86_64:
            tmp = "AMD x86-64";
            break;

        case EM_VAX:
            tmp = "DEC Vax";
            break;
        
        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_machine:", h->ehdr->e_machine, tmp);

    switch (h->ehdr->e_version) {
        case EV_NONE:
            tmp = "Invalid version";
            break;

        case EV_CURRENT:
            tmp = "Current version";
            break;

        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_version:", h->ehdr->e_version, tmp);
    PRINT_HEADER_EXP(nr++, "e_entry:", h->ehdr->e_entry, "Entry point address");
    PRINT_HEADER_EXP(nr++, "e_phoff:", h->ehdr->e_phoff, "Start of program headers");
    PRINT_HEADER_EXP(nr++, "e_shoff:", h->ehdr->e_shoff, "Start of section headers");
    PRINT_HEADER(nr++, "e_flags:", h->ehdr->e_flags);
    PRINT_HEADER_EXP(nr++, "e_ehsize:", h->ehdr->e_ehsize, "Size of this header");
    PRINT_HEADER_EXP(nr++, "e_phentsize:", h->ehdr->e_phentsize, "Size of program headers");
    PRINT_HEADER_EXP(nr++, "e_phnum:", h->ehdr->e_phnum, "Number of program headers");
    PRINT_HEADER_EXP(nr++, "e_shentsize:", h->ehdr->e_shentsize, "Size of section headers");
    PRINT_HEADER_EXP(nr++, "e_shnum:", h->ehdr->e_shnum, "Number of section headers");
    PRINT_HEADER_EXP(nr++, "e_shstrndx:", h->ehdr->e_shstrndx, "Section header string table index");
}

/**
 * @description: Section information
 * @param {handle_t32} h
 * @return {void}
 */
static void display_section32(handle_t32 *h) {
    char *name;
    char *tmp;
    char flag[4];
    INFO("Section Header Table\n");
    PRINT_SECTION_TITLE("Nr", "Name", "Type", "Addr", "Off", "Size", "Es", "Flg", "Lk", "Inf", "Al");
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            exit(-1);
        }

        switch (h->shdr[i].sh_type) {
            case SHT_NULL:
                tmp = "SHT_NULL";
                break;
            
            case SHT_PROGBITS:
                tmp = "SHT_PROGBITS";
                break;

            case SHT_SYMTAB:
                tmp = "SHT_SYMTAB";
                break;

            case SHT_STRTAB:
                tmp = "SHT_STRTAB";
                break;

            case SHT_RELA:
                tmp = "SHT_RELA";
                break;

            case SHT_HASH:
                tmp = "SHT_HASH";
                break;

            case SHT_DYNAMIC:
                tmp = "SHT_DYNAMIC";
                break;

            case SHT_NOTE:
                tmp = "SHT_NOTE";
                break;

            case SHT_NOBITS:
                tmp = "SHT_NOBITS";
                break;

            case SHT_REL:
                tmp = "SHT_REL";
                break;

            case SHT_SHLIB:
                tmp = "SHT_SHLIB";
                break;

            case SHT_DYNSYM:
                tmp = "SHT_DYNSYM";
                break;

            case SHT_LOPROC:
                tmp = "SHT_LOPROC";
                break;

            case SHT_HIPROC:
                tmp = "SHT_HIPROC";
                break;

            case SHT_LOUSER:
                tmp = "SHT_LOUSER";
                break;

            case SHT_HIUSER:
                tmp = "SHT_HIUSER";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }

        if (strlen(name) > 15) {
            strcpy(&name[15 - 6], "[...]");
        }
        strcpy(flag, "   ");
        flag2str_sh(h->shdr[i].sh_flags, flag);
        PRINT_SECTION(i, name, tmp, h->shdr[i].sh_addr, h->shdr[i].sh_offset, h->shdr[i].sh_size, h->shdr[i].sh_entsize, \
                        flag, h->shdr[i].sh_link, h->shdr[i].sh_info, h->shdr[i].sh_addralign);
    }
}

static void display_section64(handle_t64 *h) {
    char *name;
    char *tmp;
    char flag[4];
    INFO("Section Header Table\n");
    PRINT_SECTION_TITLE("Nr", "Name", "Type", "Addr", "Off", "Size", "Es", "Flg", "Lk", "Inf", "Al");
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            exit(-1);
        }

        switch (h->shdr[i].sh_type) {
            case SHT_NULL:
                tmp = "SHT_NULL";
                break;
            
            case SHT_PROGBITS:
                tmp = "SHT_PROGBITS";
                break;

            case SHT_SYMTAB:
                tmp = "SHT_SYMTAB";
                break;

            case SHT_STRTAB:
                tmp = "SHT_STRTAB";
                break;

            case SHT_RELA:
                tmp = "SHT_RELA";
                break;

            case SHT_HASH:
                tmp = "SHT_HASH";
                break;

            case SHT_DYNAMIC:
                tmp = "SHT_DYNAMIC";
                break;

            case SHT_NOTE:
                tmp = "SHT_NOTE";
                break;

            case SHT_NOBITS:
                tmp = "SHT_NOBITS";
                break;

            case SHT_REL:
                tmp = "SHT_REL";
                break;

            case SHT_SHLIB:
                tmp = "SHT_SHLIB";
                break;

            case SHT_DYNSYM:
                tmp = "SHT_DYNSYM";
                break;

            case SHT_LOPROC:
                tmp = "SHT_LOPROC";
                break;

            case SHT_HIPROC:
                tmp = "SHT_HIPROC";
                break;

            case SHT_LOUSER:
                tmp = "SHT_LOUSER";
                break;

            case SHT_HIUSER:
                tmp = "SHT_HIUSER";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }

        if (strlen(name) > 15) {
            strcpy(&name[15 - 6], "[...]");
        }
        strcpy(flag, "   ");
        flag2str_sh(h->shdr[i].sh_flags, flag);
        PRINT_SECTION(i, name, tmp, h->shdr[i].sh_addr, h->shdr[i].sh_offset, h->shdr[i].sh_size, h->shdr[i].sh_entsize, \
                        flag, h->shdr[i].sh_link, h->shdr[i].sh_info, h->shdr[i].sh_addralign);
    }
}

/**
 * @description: Segmentation information
 * @param {handle_t32} h
 * @return {void}
 */
static void display_segment32(handle_t32 *h) {
    char *name;
    char *tmp;
    char flag[4];
    INFO("Program Header Table\n");
    PRINT_PROGRAM_TITLE("Nr", "Type", "Offset", "Virtaddr", "Physaddr", "Filesiz", "Memsiz", "Flg", "Align");
    for (int i = 0; i < h->ehdr->e_phnum; i++) {
        switch (h->phdr[i].p_type) {
            case PT_NULL:
                tmp = "PT_NULL";
                break;
            
            case PT_LOAD:
                tmp = "PT_LOAD";
                break;

            case PT_DYNAMIC:
                tmp = "PT_DYNAMIC";
                break;

            case PT_INTERP:
                tmp = "PT_INTERP";
                break;

            case PT_NOTE:
                tmp = "PT_NOTE";
                break;

            case PT_SHLIB:
                tmp = "PT_SHLIB";
                break;

            case PT_PHDR:
                tmp = "PT_PHDR";
                break;

            case PT_LOPROC:
                tmp = "PT_LOPROC";
                break;

            case PT_HIPROC:
                tmp = "PT_HIPROC";
                break;

            case PT_GNU_STACK:
                tmp = "PT_GNU_STACK";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }
        strcpy(flag, "   ");
        flag2str(h->phdr[i].p_flags, flag);
        PRINT_PROGRAM(i, tmp, h->phdr[i].p_offset, h->phdr[i].p_vaddr, h->phdr[i].p_paddr, h->phdr[i].p_filesz, h->phdr[i].p_memsz, flag, h->phdr[i].p_align); 
    }

    INFO("Section to segment mapping\n");
    for (int i = 0; i < h->ehdr->e_phnum; i++) {
        printf("     [%2d]", i);
        for (int j = 0; j < h->ehdr->e_shnum; j++) {
            name = h->mem + h->shstrtab->sh_offset + h->shdr[j].sh_name;
            if (h->shdr[j].sh_addr >= h->phdr[i].p_vaddr && h->shdr[j].sh_addr + h->shdr[j].sh_size <= h->phdr[i].p_vaddr + h->phdr[i].p_memsz && h->shdr[j].sh_type != SHT_NULL) {
                if (h->shdr[j].sh_flags >> 1 & 0x1) {
                    if (name != NULL) {
                        printf(" %s", name);
                    }
                }
            }    
        }
        printf("\n");
    }
}

static void display_segment64(handle_t64 *h) {
    char *name;
    char *tmp;
    char flag[4];
    INFO("Program Header Table\n");
    PRINT_PROGRAM_TITLE("Nr", "Type", "Offset", "Virtaddr", "Physaddr", "Filesiz", "Memsiz", "Flg", "Align");
    for (int i = 0; i < h->ehdr->e_phnum; i++) {
        switch (h->phdr[i].p_type) {
            case PT_NULL:
                tmp = "PT_NULL";
                break;
            
            case PT_LOAD:
                tmp = "PT_LOAD";
                break;

            case PT_DYNAMIC:
                tmp = "PT_DYNAMIC";
                break;

            case PT_INTERP:
                tmp = "PT_INTERP";
                break;

            case PT_NOTE:
                tmp = "PT_NOTE";
                break;

            case PT_SHLIB:
                tmp = "PT_SHLIB";
                break;

            case PT_PHDR:
                tmp = "PT_PHDR";
                break;

            case PT_LOPROC:
                tmp = "PT_LOPROC";
                break;

            case PT_HIPROC:
                tmp = "PT_HIPROC";
                break;

            case PT_GNU_STACK:
                tmp = "PT_GNU_STACK";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }
        strcpy(flag, "   ");
        flag2str(h->phdr[i].p_flags, flag);
        PRINT_PROGRAM(i, tmp, h->phdr[i].p_offset, h->phdr[i].p_vaddr, h->phdr[i].p_paddr, h->phdr[i].p_filesz, h->phdr[i].p_memsz, flag, h->phdr[i].p_align); 
    }

    INFO("Section to segment mapping\n");
    for (int i = 0; i < h->ehdr->e_phnum; i++) {
        printf("     [%2d]", i);
        for (int j = 0; j < h->ehdr->e_shnum; j++) {
            name = h->mem + h->shstrtab->sh_offset + h->shdr[j].sh_name;
            if (h->shdr[j].sh_addr >= h->phdr[i].p_vaddr && h->shdr[j].sh_addr + h->shdr[j].sh_size <= h->phdr[i].p_vaddr + h->phdr[i].p_memsz && h->shdr[j].sh_type != SHT_NULL) {
                if (h->shdr[j].sh_flags >> 1 & 0x1) {
                    if (name != NULL) {
                        printf(" %s", name);
                    }                    
                }
            }    
        }
        printf("\n");
    }    
}

/**
 * @description: .dynsym information
 * @param {handle_t32} h
 * @return {void}
 */
static void display_dynsym32(handle_t32 *h, char *section_name, char *str_tab) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    int dynstr_index;
    int dynsym_index;
    size_t count;
    Elf32_Sym *sym;
    INFO("%s table\n", section_name);
    PRINT_DYNSYM_TITLE("Nr", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, str_tab)) {
            dynstr_index = i;
        }

        if (!strcmp(name, section_name)) {
            dynsym_index = i;
        }
    }
    
    name = h->mem + h->shstrtab->sh_offset + h->shdr[dynsym_index].sh_name;
    /* security check start*/
    if (validated_offset(name, h->mem, h->mem + h->size)) {
        ERROR("Corrupt file format\n");
        exit(-1);
    }

    if (!strcmp(section_name, name)) {
        sym = (Elf32_Sym *)&h->mem[h->shdr[dynsym_index].sh_offset];
        count = h->shdr[dynsym_index].sh_size / sizeof(Elf32_Sym);
        for(int i = 0; i < count; i++) {
            switch (ELF32_ST_TYPE(sym[i].st_info))
            {
                case STT_NOTYPE:
                    type = "NOTYPE";
                    break;
                
                case STT_OBJECT:
                    type = "OBJECT";
                    break;
                
                case STT_FUNC:
                    type = "FUNC";
                    break; 
                
                case STT_SECTION:
                    type = "SECTION";
                    break;
                
                case STT_FILE:
                    type = "FILE";
                    break;

                case STT_COMMON:
                    type = "COMMON";
                    break;

                case STT_TLS:
                    type = "TLS";
                    break;

                case STT_NUM:
                    type = "NUM";
                    break;
                
                case STT_LOOS:
                    type = "LOOS|GNU_IFUNC";
                    break;

                case STT_HIOS:
                    type = "HIOS";
                    break;

                case STT_LOPROC:
                    type = "LOPROC";
                    break;
                
                case STT_HIPROC:
                    type = "HIPROC";
                    break;                                                      
                
                default:
                    type = UNKOWN;
                    break;
            }

            switch (ELF32_ST_BIND(sym[i].st_info))
            {
                case STB_LOCAL:
                    bind = "LOCAL";
                    break;
                
                case STB_GLOBAL:
                    bind = "GLOBAL";
                    break;
                
                case STB_WEAK:
                    bind = "WEAK";
                    break; 
                
                case STB_NUM:
                    bind = "NUM";
                    break;
                
                case STB_LOOS:
                    bind = "LOOS|GNU_UNIQUE";
                    break;

                case STB_HIOS:
                    bind = "HIOS";
                    break;

                case STB_LOPROC:
                    bind = "LOPROC";
                    break;

                case STB_HIPROC:
                    bind = "HIPROC";
                    break;
                                                    
                default:
                    bind = UNKOWN; 
                    break;
            }

            switch (ELF32_ST_VISIBILITY(sym[i].st_other))
            {
                case STV_DEFAULT:
                    other = "DEFAULT";
                    break;

                case STV_INTERNAL:
                    other = "INTERNAL";
                    break;
                
                case STV_HIDDEN:
                    other = "HIDDEN";
                    break;
                
                case STV_PROTECTED:
                    other = "PROTECTED";
                    break;

                default:
                    other = UNKOWN;
                    break;
            }
            name = h->mem + h->shdr[dynstr_index].sh_offset + sym[i].st_name;
            if (strlen(name) > 15) {
                strcpy(&name[15 - 6], "[...]");
            }
            PRINT_DYNSYM(i, sym[i].st_value, sym[i].st_size, type, bind, \
                other, sym[i].st_shndx, name);
        }
    }
}

/**
 * @description: .dynsym information
 * @param {handle_t64} h
 * @return {void}
 */
static void display_dynsym64(handle_t64 *h, char *section_name, char *str_tab) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    int dynstr_index;
    int dynsym_index;
    size_t count;
    Elf64_Sym *sym;
    INFO("%s table\n", section_name);
    PRINT_DYNSYM_TITLE("Nr", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, str_tab)) {
            dynstr_index = i;
        }

        if (!strcmp(name, section_name)) {
            dynsym_index = i;
        }
    }
    
    name = h->mem + h->shstrtab->sh_offset + h->shdr[dynsym_index].sh_name;
    /* security check start*/
    if (validated_offset(name, h->mem, h->mem + h->size)) {
        ERROR("Corrupt file format\n");
        exit(-1);
    }

    if (!strcmp(section_name, name)) {
        sym = (Elf64_Sym *)&h->mem[h->shdr[dynsym_index].sh_offset];
        count = h->shdr[dynsym_index].sh_size / sizeof(Elf64_Sym);
        for(int i = 0; i < count; i++) {
            switch (ELF64_ST_TYPE(sym[i].st_info))
            {
                case STT_NOTYPE:
                    type = "NOTYPE";
                    break;
                
                case STT_OBJECT:
                    type = "OBJECT";
                    break;
                
                case STT_FUNC:
                    type = "FUNC";
                    break; 
                
                case STT_SECTION:
                    type = "SECTION";
                    break;
                
                case STT_FILE:
                    type = "FILE";
                    break;

                case STT_COMMON:
                    type = "COMMON";
                    break;

                case STT_TLS:
                    type = "TLS";
                    break;

                case STT_NUM:
                    type = "NUM";
                    break;
                
                case STT_LOOS:
                    type = "LOOS|GNU_IFUNC";
                    break;

                case STT_HIOS:
                    type = "HIOS";
                    break;

                case STT_LOPROC:
                    type = "LOPROC";
                    break;
                
                case STT_HIPROC:
                    type = "HIPROC";
                    break;                                                      
                
                default:
                    type = UNKOWN;
                    break;
            }

            switch (ELF64_ST_BIND(sym[i].st_info))
            {
                case STB_LOCAL:
                    bind = "LOCAL";
                    break;
                
                case STB_GLOBAL:
                    bind = "GLOBAL";
                    break;
                
                case STB_WEAK:
                    bind = "WEAK";
                    break; 
                
                case STB_NUM:
                    bind = "NUM";
                    break;
                
                case STB_LOOS:
                    bind = "LOOS|GNU_UNIQUE";
                    break;

                case STB_HIOS:
                    bind = "HIOS";
                    break;

                case STB_LOPROC:
                    bind = "LOPROC";
                    break;

                case STB_HIPROC:
                    bind = "HIPROC";
                    break;
                                                    
                default:
                    bind = UNKOWN; 
                    break;
            }

            switch (ELF64_ST_VISIBILITY(sym[i].st_other))
            {
                case STV_DEFAULT:
                    other = "DEFAULT";
                    break;

                case STV_INTERNAL:
                    other = "INTERNAL";
                    break;
                
                case STV_HIDDEN:
                    other = "HIDDEN";
                    break;
                
                case STV_PROTECTED:
                    other = "PROTECTED";
                    break;

                default:
                    other = UNKOWN;
                    break;
            }
            name = h->mem + h->shdr[dynstr_index].sh_offset + sym[i].st_name;
            if (strlen(name) > 15) {
                strcpy(&name[15 - 6], "[...]");
            }
            PRINT_DYNSYM(i, sym[i].st_value, sym[i].st_size, type, bind, \
                other, sym[i].st_shndx, name);
        }
    }
}

/**
 * @description: Dynamic link information
 * @param {handle_t32} h
 * @return {void}
 */
static void display_dyninfo32(handle_t32 *h) {
    char *name;
    int count;
    char *tmp;
    INFO("Dynamic link information\n");
    int dynstr;
    int dynamic;
    Elf32_Dyn *dyn;
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;

        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, ".dynstr")) {
            dynstr = i;
        }

        if (!strcmp(name, ".dynamic")) {
            dynamic = i;
        }
    }

    char value[50];
    name = "";
    dyn = (Elf32_Dyn *)&h->mem[h->shdr[dynamic].sh_offset];
    count = h->shdr[dynamic].sh_size / sizeof(Elf32_Dyn);
    INFO("Dynamic section at offset 0x%x contains %d entries\n", h->shdr[dynamic].sh_offset, count);
    PRINT_DYN_TITLE("Tag", "Type", "Name/Value");
    
    for(int i = 0; i < count; i++) {
        memset(value, 0, 50);
        snprintf(value, 50, "0x%x", dyn[i].d_un.d_val);
        switch (dyn[i].d_tag) {
            /* Legal values for d_tag (dynamic entry type).  */
            case DT_NULL:
                tmp = "DT_NULL";
                break;

            case DT_NEEDED:
                tmp = "DT_NEEDED";
                name = h->mem + h->shdr[dynstr].sh_offset + dyn[i].d_un.d_val;
                snprintf(value, 50, "Shared library: [%s]", name);
                break;
            
            case DT_PLTRELSZ:
                tmp = "DT_PLTRELSZ";
                break;

            case DT_PLTGOT:
                tmp = "DT_PLTGOT";
                break;

            case DT_HASH:
                tmp = "DT_HASH";
                break;

            case DT_STRTAB:
                tmp = "DT_STRTAB";
                break;

            case DT_SYMTAB:
                tmp = "DT_SYMTAB";
                break;

            case DT_RELA:
                tmp = "DT_RELA";
                break;

            case DT_RELASZ:
                tmp = "DT_RELASZ";
                break;

            case DT_RELAENT:
                tmp = "DT_RELAENT";
                break;

            case DT_STRSZ:
                tmp = "DT_STRSZ";
                break;

            case DT_SYMENT:
                tmp = "DT_SYMENT";
                break;

            case DT_INIT:
                tmp = "DT_INIT";
                break;

            case DT_FINI:
                tmp = "DT_FINI";
                break;

            case DT_SONAME:
                tmp = "DT_SONAME";
                break;

            case DT_RPATH:
                tmp = "DT_RPATH";
                break;

            case DT_SYMBOLIC:
                tmp = "DT_SYMBOLIC";
                break;

            case DT_REL:
                tmp = "DT_REL";
                break;

            case DT_RELSZ:
                tmp = "DT_RELSZ";
                break;

            case DT_RELENT:
                tmp = "DT_RELENT";
                break;
                
            case DT_PLTREL:
                tmp = "DT_PLTREL";
                break;

            case DT_DEBUG:
                tmp = "DT_DEBUG";
                break;

            case DT_TEXTREL:
                tmp = "DT_TEXTREL";
                break;

            case DT_JMPREL:
                tmp = "DT_JMPREL";
                break;

            case DT_BIND_NOW:
                tmp = "DT_BIND_NOW";
                break;

            case DT_INIT_ARRAY:
                tmp = "DT_INIT_ARRAY";
                break;

            case DT_FINI_ARRAY:
                tmp = "DT_FINI_ARRAY";
                break;

            case DT_INIT_ARRAYSZ:
                tmp = "DT_INIT_ARRAYSZ";
                break;
            
            case DT_FINI_ARRAYSZ:
                tmp = "DT_FINI_ARRAYSZ";
                break;

            case DT_RUNPATH:
                tmp = "DT_RUNPATH";
                break;

            case DT_FLAGS:
                tmp = "DT_FLAGS";
                snprintf(value, 50, "Flags: %d", dyn[i].d_un.d_val);
                break;
            
            case DT_ENCODING:
                tmp = "DT_ENCODING";
                break;

            case DT_PREINIT_ARRAYSZ:
                tmp = "DT_PREINIT_ARRAYSZ";
                break;

            case DT_SYMTAB_SHNDX:
                tmp = "DT_SYMTAB_SHNDX";
                break;
            
            case DT_NUM:
                tmp = "DT_NUM";
                break;

            case DT_LOOS:
                tmp = "DT_LOOS";
                break;

            case DT_HIOS:
                tmp = "DT_HIOS";
                break;

            case DT_LOPROC:
                tmp = "DT_LOPROC";
                break;

            case DT_HIPROC:
                tmp = "DT_HIPROC";
                break;

            case DT_PROCNUM:
                tmp = "DT_LOPROC";
                break;

            /* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
                * Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
                * approach. */

            case DT_VALRNGLO:
                tmp = "DT_VALRNGLO";
                break;

            case DT_GNU_PRELINKED:
                tmp = "DT_GNU_PRELINKED";
                break;
            
            case DT_GNU_CONFLICTSZ:
                tmp = "DT_GNU_CONFLICTSZ";
                break;

            case DT_GNU_LIBLISTSZ:
                tmp = "DT_GNU_LIBLISTSZ";
                break;

            case DT_CHECKSUM:
                tmp = "DT_CHECKSUM";
                break;

            case DT_PLTPADSZ:
                tmp = "DT_PLTPADSZ";
                break;

            case DT_MOVEENT:
                tmp = "DT_MOVEENT";
                break;

            case DT_MOVESZ:
                tmp = "DT_MOVESZ";
                break;

            case DT_FEATURE_1:
                tmp = "DT_FEATURE_1";
                break;

            case DT_POSFLAG_1:
                tmp = "DT_POSFLAG_1";
                break;

            case DT_SYMINSZ:
                tmp = "DT_SYMINSZ";
                break;

            case DT_SYMINENT:
                tmp = "DT_SYMINENT";
                break;

            /* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
                * Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
                * If any adjustment is made to the ELF object after it has been
                * built these entries will need to be adjusted.  */
            case DT_ADDRRNGLO:
                tmp = "DT_ADDRRNGLO";
                break;

            case DT_GNU_HASH:
                tmp = "DT_GNU_HASH";
                break;

            case DT_TLSDESC_PLT:
                tmp = "DT_TLSDESC_PLT";
                break;

            case DT_TLSDESC_GOT:
                tmp = "DT_TLSDESC_GOT";
                break;

            case DT_GNU_CONFLICT:
                tmp = "DT_GNU_CONFLICT";
                break;

            case DT_GNU_LIBLIST:
                tmp = "DT_GNU_LIBLIST";
                break;

            case DT_CONFIG:
                tmp = "DT_CONFIG";
                break;

            case DT_DEPAUDIT:
                tmp = "DT_DEPAUDIT";
                break;

            case DT_AUDIT:
                tmp = "DT_AUDIT";
                break;

            case DT_PLTPAD:
                tmp = "DT_PLTPAD";
                break;

            case DT_MOVETAB:
                tmp = "DT_MOVETAB";
                break;

            case DT_SYMINFO:
                tmp = "DT_SYMINFO";
                break;
                
            /* The versioning entry types.  The next are defined as part of the
                * GNU extension.  */
            case DT_VERSYM:
                tmp = "DT_VERSYM";
                break;

            case DT_RELACOUNT:
                tmp = "DT_RELACOUNT";
                break;

            case DT_RELCOUNT:
                tmp = "DT_RELCOUNT";
                break;
            
            /* These were chosen by Sun.  */
            case DT_FLAGS_1:
                tmp = "DT_FLAGS_1";
                switch (dyn[i].d_un.d_val) {
                    case DF_1_PIE:
                        snprintf(value, 50, "Flags: %s", "PIE");
                        break;
                    
                    default:
                        snprintf(value, 50, "Flags: %d", dyn[i].d_un.d_val);
                        break;
                }
                
                break;

            case DT_VERDEF:
                tmp = "DT_VERDEF";
                break;

            case DT_VERDEFNUM:
                tmp = "DT_VERDEFNUM";
                break;

            case DT_VERNEED:
                tmp = "DT_VERNEED";
                break;

            case DT_VERNEEDNUM:
                tmp = "DT_VERNEEDNUM";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }
        PRINT_DYN(dyn[i].d_tag, tmp, value);
    }
}

static void display_dyninfo64(handle_t64 *h) {
    char *name;
    int count;
    char *tmp;
    INFO("Dynamic link information\n");
    int dynstr;
    int dynamic;
    Elf64_Dyn *dyn;
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, ".dynstr")) {
            dynstr = i;
        }

        if (!strcmp(name, ".dynamic")) {
            dynamic = i;
        }
    }

    char value[50];
    name = "";
    dyn = (Elf64_Dyn *)&h->mem[h->shdr[dynamic].sh_offset];
    count = h->shdr[dynamic].sh_size / sizeof(Elf64_Dyn);
    INFO("Dynamic section at offset 0x%x contains %d entries\n", h->shdr[dynamic].sh_offset, count);
    PRINT_DYN_TITLE("Tag", "Type", "Name/Value");
    
    for(int i = 0; i < count; i++) {
        memset(value, 0, 50);
        snprintf(value, 50, "0x%x", dyn[i].d_un.d_val);
        switch (dyn[i].d_tag) {
            /* Legal values for d_tag (dynamic entry type).  */
            case DT_NULL:
                tmp = "DT_NULL";
                break;

            case DT_NEEDED:
                tmp = "DT_NEEDED";
                name = h->mem + h->shdr[dynstr].sh_offset + dyn[i].d_un.d_val;
                snprintf(value, 50, "Shared library: [%s]", name);
                break;
            
            case DT_PLTRELSZ:
                tmp = "DT_PLTRELSZ";
                break;

            case DT_PLTGOT:
                tmp = "DT_PLTGOT";
                break;

            case DT_HASH:
                tmp = "DT_HASH";
                break;

            case DT_STRTAB:
                tmp = "DT_STRTAB";
                break;

            case DT_SYMTAB:
                tmp = "DT_SYMTAB";
                break;

            case DT_RELA:
                tmp = "DT_RELA";
                break;

            case DT_RELASZ:
                tmp = "DT_RELASZ";
                break;

            case DT_RELAENT:
                tmp = "DT_RELAENT";
                break;

            case DT_STRSZ:
                tmp = "DT_STRSZ";
                break;

            case DT_SYMENT:
                tmp = "DT_SYMENT";
                break;

            case DT_INIT:
                tmp = "DT_INIT";
                break;

            case DT_FINI:
                tmp = "DT_FINI";
                break;

            case DT_SONAME:
                tmp = "DT_SONAME";
                break;

            case DT_RPATH:
                tmp = "DT_RPATH";
                break;

            case DT_SYMBOLIC:
                tmp = "DT_SYMBOLIC";
                break;

            case DT_REL:
                tmp = "DT_REL";
                break;

            case DT_RELSZ:
                tmp = "DT_RELSZ";
                break;

            case DT_RELENT:
                tmp = "DT_RELENT";
                break;
                
            case DT_PLTREL:
                tmp = "DT_PLTREL";
                break;

            case DT_DEBUG:
                tmp = "DT_DEBUG";
                break;

            case DT_TEXTREL:
                tmp = "DT_TEXTREL";
                break;

            case DT_JMPREL:
                tmp = "DT_JMPREL";
                break;

            case DT_BIND_NOW:
                tmp = "DT_BIND_NOW";
                break;

            case DT_INIT_ARRAY:
                tmp = "DT_INIT_ARRAY";
                break;

            case DT_FINI_ARRAY:
                tmp = "DT_FINI_ARRAY";
                break;

            case DT_INIT_ARRAYSZ:
                tmp = "DT_INIT_ARRAYSZ";
                break;
            
            case DT_FINI_ARRAYSZ:
                tmp = "DT_FINI_ARRAYSZ";
                break;

            case DT_RUNPATH:
                tmp = "DT_RUNPATH";
                break;

            case DT_FLAGS:
                tmp = "DT_FLAGS";
                snprintf(value, 50, "Flags: %d", dyn[i].d_un.d_val);
                break;
            
            case DT_ENCODING:
                tmp = "DT_ENCODING";
                break;

            case DT_PREINIT_ARRAYSZ:
                tmp = "DT_PREINIT_ARRAYSZ";
                break;

            case DT_SYMTAB_SHNDX:
                tmp = "DT_SYMTAB_SHNDX";
                break;
            
            case DT_NUM:
                tmp = "DT_NUM";
                break;

            case DT_LOOS:
                tmp = "DT_LOOS";
                break;

            case DT_HIOS:
                tmp = "DT_HIOS";
                break;

            case DT_LOPROC:
                tmp = "DT_LOPROC";
                break;

            case DT_HIPROC:
                tmp = "DT_HIPROC";
                break;

            case DT_PROCNUM:
                tmp = "DT_LOPROC";
                break;

            /* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
                * Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
                * approach. */

            case DT_VALRNGLO:
                tmp = "DT_VALRNGLO";
                break;

            case DT_GNU_PRELINKED:
                tmp = "DT_GNU_PRELINKED";
                break;
            
            case DT_GNU_CONFLICTSZ:
                tmp = "DT_GNU_CONFLICTSZ";
                break;

            case DT_GNU_LIBLISTSZ:
                tmp = "DT_GNU_LIBLISTSZ";
                break;

            case DT_CHECKSUM:
                tmp = "DT_CHECKSUM";
                break;

            case DT_PLTPADSZ:
                tmp = "DT_PLTPADSZ";
                break;

            case DT_MOVEENT:
                tmp = "DT_MOVEENT";
                break;

            case DT_MOVESZ:
                tmp = "DT_MOVESZ";
                break;

            case DT_FEATURE_1:
                tmp = "DT_FEATURE_1";
                break;

            case DT_POSFLAG_1:
                tmp = "DT_POSFLAG_1";
                break;

            case DT_SYMINSZ:
                tmp = "DT_SYMINSZ";
                break;

            case DT_SYMINENT:
                tmp = "DT_SYMINENT";
                break;

            /* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
                * Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
                * If any adjustment is made to the ELF object after it has been
                * built these entries will need to be adjusted.  */
            case DT_ADDRRNGLO:
                tmp = "DT_ADDRRNGLO";
                break;

            case DT_GNU_HASH:
                tmp = "DT_GNU_HASH";
                break;

            case DT_TLSDESC_PLT:
                tmp = "DT_TLSDESC_PLT";
                break;

            case DT_TLSDESC_GOT:
                tmp = "DT_TLSDESC_GOT";
                break;

            case DT_GNU_CONFLICT:
                tmp = "DT_GNU_CONFLICT";
                break;

            case DT_GNU_LIBLIST:
                tmp = "DT_GNU_LIBLIST";
                break;

            case DT_CONFIG:
                tmp = "DT_CONFIG";
                break;

            case DT_DEPAUDIT:
                tmp = "DT_DEPAUDIT";
                break;

            case DT_AUDIT:
                tmp = "DT_AUDIT";
                break;

            case DT_PLTPAD:
                tmp = "DT_PLTPAD";
                break;

            case DT_MOVETAB:
                tmp = "DT_MOVETAB";
                break;

            case DT_SYMINFO:
                tmp = "DT_SYMINFO";
                break;
                
            /* The versioning entry types.  The next are defined as part of the
                * GNU extension.  */
            case DT_VERSYM:
                tmp = "DT_VERSYM";
                break;

            case DT_RELACOUNT:
                tmp = "DT_RELACOUNT";
                break;

            case DT_RELCOUNT:
                tmp = "DT_RELCOUNT";
                break;
            
            /* These were chosen by Sun.  */
            case DT_FLAGS_1:
                tmp = "DT_FLAGS_1";
                switch (dyn[i].d_un.d_val) {
                    case DF_1_PIE:
                        snprintf(value, 50, "Flags: %s", "PIE");
                        break;
                    
                    default:
                        snprintf(value, 50, "Flags: %d", dyn[i].d_un.d_val);
                        break;
                }
                
                break;

            case DT_VERDEF:
                tmp = "DT_VERDEF";
                break;

            case DT_VERDEFNUM:
                tmp = "DT_VERDEFNUM";
                break;

            case DT_VERNEED:
                tmp = "DT_VERNEED";
                break;

            case DT_VERNEEDNUM:
                tmp = "DT_VERNEEDNUM";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }
        PRINT_DYN(dyn[i].d_tag, tmp, value);
    }
}
