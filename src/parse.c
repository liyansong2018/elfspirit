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
#include <stdarg.h>
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
#define PRINT_DYN(Nr, tag, type, value) \
    printf("     [%2d] %08x   %-15s   %-30s\n", \
    Nr, tag, type, value);
#define PRINT_DYN_TITLE(Nr, tag, type, value) \
    printf("     [%2s] %-10s   %-15s   %-30s\n", \
    Nr, tag, type, value);

/* print .rela */
#define PRINT_RELA(Nr, offset, info, type, value, name) \
    printf("     [%2d] %016x %016x %-18s %-10x %-16s\n", \
    Nr, offset, info, type, value, name);
#define PRINT_RELA_TITLE(Nr, offset, info, type, value, name) \
    printf("     [%2s] %-16s %-16s %-18s %-10s %-16s\n", \
    Nr, offset, info, type, value, name);

/* print pointer */
#define PRINT_POINTER32(Nr, value, name) \
    printf("     [%2d] %08x %-16s\n", \
    Nr, value, name);
#define PRINT_POINTER32_TITLE(Nr, value, name) \
    printf("     [%2s] %-08s %-16s\n", \
    Nr, value, name);

#define PRINT_POINTER64(Nr, value, name) \
    printf("     [%2d] %016x %-16s\n", \
    Nr, value, name);
#define PRINT_POINTER64_TITLE(Nr, value, name) \
    printf("     [%2s] %-016s %-16s\n", \
    Nr, value, name);

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

// 函数用于检查整数是否包含特定的宏标志位
int has_flag(int num, int flag) {
    return (num & flag) == flag;
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

#define STR_NUM 0x4096
#define STR_LENGTH 0x1024
struct MyStr {
    size_t count;
    uint64_t value[STR_NUM];
    char name[STR_NUM][STR_LENGTH];
};
struct MyStr g_dynsym;
struct MyStr g_symtab;
struct MyStr g_secname;
uint32_t g_strlength;

void static init() {
    memset(&g_dynsym, 0, sizeof(struct MyStr));
    memset(&g_symtab, 0, sizeof(struct MyStr));
    memset(&g_secname, 0, sizeof(struct MyStr));
    g_strlength = 0;
}

static void display_header32(handle_t32 *);
static void display_header64(handle_t64 *);
static void display_section32(handle_t32 *, int is_display);
static void display_section64(handle_t64 *, int is_display);
static void display_segment32(handle_t32 *);
static void display_segment64(handle_t64 *);
static void display_dynsym32(handle_t32 *, char *section_name, char *str_tab, int is_display);
static void display_dynsym64(handle_t64 *, char *section_name, char *str_tab, int is_display);
static void display_dyninfo32(handle_t32 *);
static void display_dyninfo64(handle_t64 *);
static int display_rel32(handle_t32 *, char *section_name);
static int display_rel64(handle_t64 *, char *section_name);
static int display_rela32(handle_t32 *, char *section_name);
static int display_rela64(handle_t64 *, char *section_name);
static int display_pointer32(handle_t32 *, int, ...);
static int display_pointer64(handle_t64 *, int, ...);

int parse(char *elf, parser_opt_t *po, uint32_t length) {
    int fd;
    struct stat st;
    uint8_t *elf_map = NULL;
    int count = 0;
    char *tmp = NULL;
    char *name = NULL;
    char flag[4] = "\0";

    init();

    if (!length) {
        g_strlength = 15;
    } else {
        g_strlength = length;
    }

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
            display_section32(&h, 1);

        /* Segmentation Information */
        if (!get_option(po, SEGMENTS) || !get_option(po, ALL))
            display_segment32(&h);

        /* .dynsym information */
        if (!get_option(po, DYNSYM) || !get_option(po, ALL)){
            display_dynsym32(&h, ".dynsym", ".dynstr", 1);
        }

        /* .symtab information */
        if (!get_option(po, SYMTAB) || !get_option(po, ALL)){
            display_dynsym32(&h, ".symtab", ".strtab", 1);
        }

        /* .dynamic Infomation */
        if (!get_option(po, LINK) || !get_option(po, ALL))
            display_dyninfo32(&h);  

        /* .rela.dyn .rela.plt Infomation */
        if (!get_option(po, RELA) || !get_option(po, ALL)) {
            if (g_dynsym.count == 0)
                display_dynsym32(&h, ".dynsym", ".dynstr", 0);  // get dynamic symbol name
            if (g_symtab.count == 0)
                display_dynsym32(&h, ".symtab", ".strtab", 0);  // get symbol name
            if (g_secname.count == 0)
                display_section32(&h, 0);                       // get section name
            for (int i = 0; i < g_secname.count; i++) {
                if (compare_firstN_chars(g_secname.name[i], ".rela", 5)) {
                    display_rela32(&h, g_secname.name[i]);
                } else if (compare_firstN_chars(g_secname.name[i], ".rel", 4)){
                    display_rel32(&h, g_secname.name[i]);
                }
            }
        } 

        /* elf pointer */
        if (!get_option(po, POINTER) || !get_option(po, ALL)) {
            if (g_symtab.count == 0)
                display_dynsym32(&h, ".symtab", ".strtab", 0);  // get symbol name
            display_pointer32(&h, 5, ".init_array", ".fini_array", ".ctors", ".dtors", ".eh_frame_hdr");  
        }        
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
            display_section64(&h, 1);

        /* Segmentation Information */
        if (!get_option(po, SEGMENTS) || !get_option(po, ALL))
            display_segment64(&h);

        /* .dynsym information */
        if (!get_option(po, DYNSYM) || !get_option(po, ALL)){
            display_dynsym64(&h, ".dynsym", ".dynstr", 1);
        }

        /* .symtab information */
        if (!get_option(po, SYMTAB) || !get_option(po, ALL)){
            display_dynsym64(&h, ".symtab", ".strtab", 1);
        }

        /* .dynamic Infomation */
        if (!get_option(po, LINK) || !get_option(po, ALL))
            display_dyninfo64(&h);      

        /* .rela.dyn .rela.plt Infomation */
        if (!get_option(po, RELA) || !get_option(po, ALL)) {
            if (g_dynsym.count == 0)
                display_dynsym64(&h, ".dynsym", ".dynstr", 0);  // get dynamic symbol name
            if (g_symtab.count == 0)
                display_dynsym64(&h, ".symtab", ".strtab", 0);  // get symbol name
            if (g_secname.count == 0)
                display_section64(&h, 0);                       // get section name
            for (int i = 0; i < g_secname.count; i++) {
                if (compare_firstN_chars(g_secname.name[i], ".rela", 5)) {
                    display_rela64(&h, g_secname.name[i]);
                } else if (compare_firstN_chars(g_secname.name[i], ".rel", 4)){
                    display_rel64(&h, g_secname.name[i]);
                }
            }
        }
        
        /* elf pointer */
        if (!get_option(po, POINTER) || !get_option(po, ALL))    
            if (g_symtab.count == 0)
                display_dynsym64(&h, ".symtab", ".strtab", 0);  // get symbol name
            display_pointer64(&h, 5, ".init_array", ".fini_array", ".ctors", ".dtors", ".eh_frame_hdr");
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
static void display_section32(handle_t32 *h, int is_display) {
    char *name;
    char *tmp;
    char flag[4];
    if (is_display) {
        INFO("Section Header Table\n");
        PRINT_SECTION_TITLE("Nr", "Name", "Type", "Addr", "Off", "Size", "Es", "Flg", "Lk", "Inf", "Al");
    }

    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        /* store section name */
        if (i < STR_NUM && strlen(name) < STR_LENGTH){
            g_secname.count++;
            strcpy(g_secname.name[i], name);
        }
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

        if (strlen(name) > g_strlength) {
            strcpy(&name[g_strlength - 6], "[...]");
        }
        strcpy(flag, "   ");
        flag2str_sh(h->shdr[i].sh_flags, flag);
        if (is_display)
        PRINT_SECTION(i, name, tmp, h->shdr[i].sh_addr, h->shdr[i].sh_offset, h->shdr[i].sh_size, h->shdr[i].sh_entsize, \
                        flag, h->shdr[i].sh_link, h->shdr[i].sh_info, h->shdr[i].sh_addralign);
    }
}

static void display_section64(handle_t64 *h, int is_display) {
    char *name;
    char *tmp;
    char flag[4];
    if (is_display) {
        INFO("Section Header Table\n");
        PRINT_SECTION_TITLE("Nr", "Name", "Type", "Addr", "Off", "Size", "Es", "Flg", "Lk", "Inf", "Al");
    }
    
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        /* store section name */
        if (i < STR_NUM && strlen(name) < STR_LENGTH){
            g_secname.count++;
            strcpy(g_secname.name[i], name);
        }
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

        if (strlen(name) > g_strlength) {
            strcpy(&name[g_strlength - 6], "[...]");
        }
        strcpy(flag, "   ");
        flag2str_sh(h->shdr[i].sh_flags, flag);
        if (is_display)
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
                printf("\t\t[Requesting program interpreter: %s]\n", h->mem + h->phdr[i].p_offset);
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
                printf("\t\t[Requesting program interpreter: %s]\n", h->mem + h->phdr[i].p_offset);
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
static void display_dynsym32(handle_t32 *h, char *section_name, char *str_tab, int is_display) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    // The following variables must be initialized 
    // because they need to be used to determine whether sections exist or not.
    // 以下些变量必须初始化，因为要根据他们判节是否存在
    int dynstr_index = 0;
    int dynsym_index = 0;
    size_t count;
    Elf32_Sym *sym;

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

    if (!dynstr_index) {
        WARNING("This file does not have a %s\n", str_tab);
        return -1;
    }

    if (!dynsym_index) {
        WARNING("This file does not have a %s\n", section_name);
        return -1;
    }

    if (is_display) {
        INFO("%s table\n", section_name);
        PRINT_DYNSYM_TITLE("Nr", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
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
            /* store */
            if (!strcmp(".symtab", section_name) && i < STR_NUM && strlen(name) < STR_LENGTH) {
                g_symtab.count++;
                g_symtab.value[i] = sym[i].st_value;
                strcpy(g_symtab.name[i], name);
            } 
            else if (!strcmp(".dynsym", section_name) &&  i < STR_NUM && strlen(name) < STR_LENGTH){
                g_dynsym.count++;
                g_dynsym.value[i] = sym[i].st_value;
                strcpy(g_dynsym.name[i], name);
            }
            /* hide long strings */
            if (strlen(name) > g_strlength) {
                strcpy(&name[g_strlength - 6], "[...]");
            }
            if (is_display)
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
static void display_dynsym64(handle_t64 *h, char *section_name, char *str_tab, int is_display) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    // The following variables must be initialized 
    // because they need to be used to determine whether sections exist or not.
    // 以下些变量必须初始化，因为要根据他们判节是否存在
    int dynstr_index = 0;
    int dynsym_index = 0;
    size_t count;
    Elf64_Sym *sym;

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

    if (!dynstr_index) {
        WARNING("This file does not have a %s\n", str_tab);
        return -1;
    }

    if (!dynsym_index) {
        WARNING("This file does not have a %s\n", section_name);
        return -1;
    }

    if (is_display) {
        INFO("%s table\n", section_name);
        PRINT_DYNSYM_TITLE("Nr", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
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
            /* store */
            if (!strcmp(".symtab", section_name) && i < STR_NUM && strlen(name) < STR_LENGTH) {
                g_symtab.count++;
                g_symtab.value[i] = sym[i].st_value;
                strcpy(g_symtab.name[i], name);
            } 
            else if (!strcmp(".dynsym", section_name) &&  i < STR_NUM && strlen(name) < STR_LENGTH){
                g_dynsym.count++;
                g_dynsym.value[i] = sym[i].st_value;
                strcpy(g_dynsym.name[i], name);
            }
            /* hide long strings */
            if (strlen(name) > g_strlength) {
                strcpy(&name[g_strlength - 6], "[...]");
            }
            if (is_display)
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

    if (!dynstr) {
        WARNING("This file does not have a %s\n", ".dynstr");
        return -1;
    }

    if (!dynamic) {
        WARNING("This file does not have a %s\n", ".dynamic");
        return -1;
    }

    char value[50];
    name = "";
    dyn = (Elf32_Dyn *)&h->mem[h->shdr[dynamic].sh_offset];
    count = h->shdr[dynamic].sh_size / sizeof(Elf32_Dyn);
    INFO("Dynamic section at offset 0x%x contains %d entries\n", h->shdr[dynamic].sh_offset, count);
    PRINT_DYN_TITLE("Nr", "Tag", "Type", "Name/Value");
    
    for(int i = 0; i < count; i++) {
        memset(value, 0, 50);
        snprintf(value, 50, "0x%x", dyn[i].d_un.d_val);
        name = h->mem + h->shdr[dynstr].sh_offset + dyn[i].d_un.d_val;
        switch (dyn[i].d_tag) {
            /* Legal values for d_tag (dynamic entry type).  */
            case DT_NULL:
                tmp = "DT_NULL";
                break;

            case DT_NEEDED:
                tmp = "DT_NEEDED";
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
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_RPATH:
                tmp = "DT_RPATH";
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
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
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_FLAGS:
                tmp = "DT_FLAGS";
                switch (dyn[i].d_un.d_val)
                {
                /* Object may use DF_ORIGIN */
                case DF_ORIGIN:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_ORIGIN");
                    break;

                /* Symbol resolutions starts here */
                case DF_SYMBOLIC:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_SYMBOLIC");
                    break;
                
                /* Object contains text relocations */
                case DF_TEXTREL:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_TEXTREL");
                    break;
                
                /* No lazy binding for this object */
                case DF_BIND_NOW:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_BIND_NOW");
                    break;

                /* Module uses the static TLS model */
                case DF_STATIC_TLS:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_STATIC_TLS");
                    break;
                
                default:
                    break;
                }

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
                int offset = 0;
                if (has_flag(dyn[i].d_un.d_val, DF_1_NOW)) {
                    offset += snprintf(value, 50, "%s ", "NOW");
                }
                if (has_flag(dyn[i].d_un.d_val, DF_1_PIE)) {
                    offset += snprintf(value + offset, 50, "%s ", "PIE");
                }
                else {
                    // TODO
                    snprintf(value, 50, "Known: 0x%x", dyn[i].d_un.d_val);
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
        PRINT_DYN(i, dyn[i].d_tag, tmp, value);
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

    if (!dynstr) {
        WARNING("This file does not have a %s\n", ".dynstr");
        return -1;
    }

    if (!dynamic) {
        WARNING("This file does not have a %s\n", ".dynamic");
        return -1;
    }

    char value[50];
    name = "";
    dyn = (Elf64_Dyn *)&h->mem[h->shdr[dynamic].sh_offset];
    count = h->shdr[dynamic].sh_size / sizeof(Elf64_Dyn);
    INFO("Dynamic section at offset 0x%x contains %d entries\n", h->shdr[dynamic].sh_offset, count);
    PRINT_DYN_TITLE("Nr", "Tag", "Type", "Name/Value");
    
    for(int i = 0; i < count; i++) {
        memset(value, 0, 50);
        snprintf(value, 50, "0x%x", dyn[i].d_un.d_val);
        name = h->mem + h->shdr[dynstr].sh_offset + dyn[i].d_un.d_val;
        switch (dyn[i].d_tag) {
            /* Legal values for d_tag (dynamic entry type).  */
            case DT_NULL:
                tmp = "DT_NULL";
                break;

            case DT_NEEDED:
                tmp = "DT_NEEDED";
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
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_RPATH:
                tmp = "DT_RPATH";
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
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
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_FLAGS:
                tmp = "DT_FLAGS";
                switch (dyn[i].d_un.d_val)
                {
                /* Object may use DF_ORIGIN */
                case DF_ORIGIN:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_ORIGIN");
                    break;

                /* Symbol resolutions starts here */
                case DF_SYMBOLIC:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_SYMBOLIC");
                    break;
                
                /* Object contains text relocations */
                case DF_TEXTREL:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_TEXTREL");
                    break;
                
                /* No lazy binding for this object */
                case DF_BIND_NOW:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_BIND_NOW");
                    break;

                /* Module uses the static TLS model */
                case DF_STATIC_TLS:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_STATIC_TLS");
                    break;
                
                default:
                    break;
                }
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
                int offset = 0;
                if (has_flag(dyn[i].d_un.d_val, DF_1_NOW)) {
                    offset += snprintf(value, 50, "%s ", "NOW");
                }
                if (has_flag(dyn[i].d_un.d_val, DF_1_PIE)) {
                    offset += snprintf(value + offset, 50, "%s ", "PIE");
                }
                else {
                    // TODO
                    snprintf(value, 50, "Known: 0x%x", dyn[i].d_un.d_val);
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
        PRINT_DYN(i, dyn[i].d_tag, tmp, value);
    }
}

/** 
 * @brief .relation information (.rel.*)
 * 
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_rel32(handle_t32 *h, char *section_name) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    int str_index;
    int rela_dyn_index;
    size_t count;
    Elf32_Rel *rel_section;
    int has_component = 0;
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            return -1;
        }

        if (!strcmp(name, section_name)) {
            rela_dyn_index = i;
            has_component = 1;
        }
    }

    if (!has_component) {
        WARNING("This file does not have a %s\n", section_name);
        return -1;
    }
    
    if (validated_offset(name, h->mem, h->mem + h->size)) {
        ERROR("Corrupt file format\n");
        return -1;
    }
    
    rel_section = (Elf32_Rel *)&h->mem[h->shdr[rela_dyn_index].sh_offset];
    count = h->shdr[rela_dyn_index].sh_size / sizeof(Elf32_Rel);
    INFO("Relocation section '%s' at offset 0x%x contains %d entries:\n", section_name, h->shdr[rela_dyn_index].sh_offset, count);
    PRINT_RELA_TITLE("Nr", "Offset", "Info", "Type", "Sym.Index", "Sym.Name(.symtab)");
    for (int i = 0; i < count; i++) {
        switch (ELF32_R_TYPE(rel_section[i].r_info))
        {
            case R_X86_64_NONE:
                type = "R_X86_64_NONE";
                break;

            case R_X86_64_64:
                type = "R_X86_64_64";
                break;

            case R_X86_64_PC32:
                type = "R_X86_64_PC32";
                break;

            case R_X86_64_GOT32:
                type = "R_X86_64_GOT32";
                break;

            case R_X86_64_PLT32:
                type = "R_X86_64_PLT32";
                break;

            case R_X86_64_COPY:
                type = "R_X86_64_COPY";
                break;

            case R_X86_64_GLOB_DAT:
                type = "R_X86_64_GLOB_DAT";
                break;

            case R_X86_64_JUMP_SLOT:
                type = "R_X86_64_JUMP_SLOT";
                break;

            case R_X86_64_RELATIVE:
                type = "R_X86_64_RELATIVE";
                break;

            case R_X86_64_GOTPCREL:
                type = "R_X86_64_GOTPCREL";
                break;

            case R_X86_64_32:
                type = "R_X86_64_32";
                break;

            case R_X86_64_32S:
                type = "R_X86_64_32S";
                break;

            case R_X86_64_16:
                type = "R_X86_64_16";
                break;

            case R_X86_64_PC16:
                type = "R_X86_64_PC16";
                break;

            case R_X86_64_8:
                type = "R_X86_64_8";
                break;

            case R_X86_64_PC8:
                type = "R_X86_64_PC8";
                break;

            case R_X86_64_DTPMOD64:
                type = "R_X86_64_DTPMOD64";
                break;

            case R_X86_64_DTPOFF64:
                type = "R_X86_64_DTPOFF64";
                break;

            case R_X86_64_TPOFF64:
                type = "R_X86_64_TPOFF64";
                break;

            case R_X86_64_TLSGD:
                type = "R_X86_64_TLSGD";
                break;

            case R_X86_64_TLSLD:
                type = "R_X86_64_TLSLD";
                break;

            case R_X86_64_DTPOFF32:
                type = "R_X86_64_DTPOFF32";
                break;

            case R_X86_64_GOTTPOFF:
                type = "R_X86_64_GOTTPOFF";
                break;

            case R_X86_64_TPOFF32:
                type = "R_X86_64_TPOFF32";
                break;

            case R_X86_64_PC64:
                type = "R_X86_64_PC64";
                break;

            case R_X86_64_GOTOFF64:
                type = "R_X86_64_GOTOFF64";
                break;

            case R_X86_64_GOTPC32:
                type = "R_X86_64_GOTPC32";
                break;

            case R_X86_64_GOT64:
                type = "R_X86_64_GOT64";
                break;

            case R_X86_64_GOTPCREL64:
                type = "R_X86_64_GOTPCREL64";
                break;

            case R_X86_64_GOTPC64:
                type = "R_X86_64_GOTPC64";
                break;

            case R_X86_64_GOTPLT64:
                type = "R_X86_64_GOTPLT64";
                break;

            case R_X86_64_PLTOFF64:
                type = "R_X86_64_PLTOFF64";
                break;

            case R_X86_64_SIZE32:
                type = "R_X86_64_SIZE32";
                break;

            case R_X86_64_SIZE64:
                type = "R_X86_64_SIZE64";
                break;

            case R_X86_64_GOTPC32_TLSDESC:
                type = "R_X86_64_GOTPC32_TLSDESC";
                break;

            case R_X86_64_TLSDESC_CALL:
                type = "R_X86_64_TLSDESC_CALL";
                break;

            case R_X86_64_TLSDESC:
                type = "R_X86_64_TLSDESC";
                break;

            case R_X86_64_IRELATIVE:
                type = "R_X86_64_IRELATIVE";
                break;

            case R_X86_64_RELATIVE64:
                type = "R_X86_64_RELATIVE64";
                break;

            case R_X86_64_GOTPCRELX:
                type = "R_X86_64_GOTPCRELX";
                break;

            case R_X86_64_REX_GOTPCRELX:
                type = "R_X86_64_REX_GOTPCRELX";
                break;

            case R_X86_64_NUM:
                type = "R_X86_64_NUM";
                break;
            
            default:
                break;
        }
        
        str_index = ELF32_R_SYM(rel_section[i].r_info);
        PRINT_RELA(i, rel_section[i].r_offset, rel_section[i].r_info, type, str_index, g_symtab.name[str_index]);
    }
    printf("\n");
}

/** 
 * @brief .relation information (.rel.*)
 * 
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_rel64(handle_t64 *h, char *section_name) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    int str_index;
    int rela_dyn_index;
    size_t count;
    Elf64_Rel *rel_section;
    int has_component = 0;
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            return -1;
        }

        if (!strcmp(name, section_name)) {
            rela_dyn_index = i;
            has_component = 1;
        }
    }

    if (!has_component) {
        WARNING("This file does not have a %s\n", section_name);
        return -1;
    }
    
    if (validated_offset(name, h->mem, h->mem + h->size)) {
        ERROR("Corrupt file format\n");
        return -1;
    }
    
    rel_section = (Elf64_Rel *)&h->mem[h->shdr[rela_dyn_index].sh_offset];
    count = h->shdr[rela_dyn_index].sh_size / sizeof(Elf64_Rel);
    INFO("Relocation section '%s' at offset 0x%x contains %d entries:\n", section_name, h->shdr[rela_dyn_index].sh_offset, count);
    PRINT_RELA_TITLE("Nr", "Offset", "Info", "Type", "Sym.Index", "Sym.Name (.symtab)");
    for (int i = 0; i < count; i++) {
        switch (ELF64_R_TYPE(rel_section[i].r_info))
        {
            case R_X86_64_NONE:
                type = "R_X86_64_NONE";
                break;

            case R_X86_64_64:
                type = "R_X86_64_64";
                break;

            case R_X86_64_PC32:
                type = "R_X86_64_PC32";
                break;

            case R_X86_64_GOT32:
                type = "R_X86_64_GOT32";
                break;

            case R_X86_64_PLT32:
                type = "R_X86_64_PLT32";
                break;

            case R_X86_64_COPY:
                type = "R_X86_64_COPY";
                break;

            case R_X86_64_GLOB_DAT:
                type = "R_X86_64_GLOB_DAT";
                break;

            case R_X86_64_JUMP_SLOT:
                type = "R_X86_64_JUMP_SLOT";
                break;

            case R_X86_64_RELATIVE:
                type = "R_X86_64_RELATIVE";
                break;

            case R_X86_64_GOTPCREL:
                type = "R_X86_64_GOTPCREL";
                break;

            case R_X86_64_32:
                type = "R_X86_64_32";
                break;

            case R_X86_64_32S:
                type = "R_X86_64_32S";
                break;

            case R_X86_64_16:
                type = "R_X86_64_16";
                break;

            case R_X86_64_PC16:
                type = "R_X86_64_PC16";
                break;

            case R_X86_64_8:
                type = "R_X86_64_8";
                break;

            case R_X86_64_PC8:
                type = "R_X86_64_PC8";
                break;

            case R_X86_64_DTPMOD64:
                type = "R_X86_64_DTPMOD64";
                break;

            case R_X86_64_DTPOFF64:
                type = "R_X86_64_DTPOFF64";
                break;

            case R_X86_64_TPOFF64:
                type = "R_X86_64_TPOFF64";
                break;

            case R_X86_64_TLSGD:
                type = "R_X86_64_TLSGD";
                break;

            case R_X86_64_TLSLD:
                type = "R_X86_64_TLSLD";
                break;

            case R_X86_64_DTPOFF32:
                type = "R_X86_64_DTPOFF32";
                break;

            case R_X86_64_GOTTPOFF:
                type = "R_X86_64_GOTTPOFF";
                break;

            case R_X86_64_TPOFF32:
                type = "R_X86_64_TPOFF32";
                break;

            case R_X86_64_PC64:
                type = "R_X86_64_PC64";
                break;

            case R_X86_64_GOTOFF64:
                type = "R_X86_64_GOTOFF64";
                break;

            case R_X86_64_GOTPC32:
                type = "R_X86_64_GOTPC32";
                break;

            case R_X86_64_GOT64:
                type = "R_X86_64_GOT64";
                break;

            case R_X86_64_GOTPCREL64:
                type = "R_X86_64_GOTPCREL64";
                break;

            case R_X86_64_GOTPC64:
                type = "R_X86_64_GOTPC64";
                break;

            case R_X86_64_GOTPLT64:
                type = "R_X86_64_GOTPLT64";
                break;

            case R_X86_64_PLTOFF64:
                type = "R_X86_64_PLTOFF64";
                break;

            case R_X86_64_SIZE32:
                type = "R_X86_64_SIZE32";
                break;

            case R_X86_64_SIZE64:
                type = "R_X86_64_SIZE64";
                break;

            case R_X86_64_GOTPC32_TLSDESC:
                type = "R_X86_64_GOTPC32_TLSDESC";
                break;

            case R_X86_64_TLSDESC_CALL:
                type = "R_X86_64_TLSDESC_CALL";
                break;

            case R_X86_64_TLSDESC:
                type = "R_X86_64_TLSDESC";
                break;

            case R_X86_64_IRELATIVE:
                type = "R_X86_64_IRELATIVE";
                break;

            case R_X86_64_RELATIVE64:
                type = "R_X86_64_RELATIVE64";
                break;

            case R_X86_64_GOTPCRELX:
                type = "R_X86_64_GOTPCRELX";
                break;

            case R_X86_64_REX_GOTPCRELX:
                type = "R_X86_64_REX_GOTPCRELX";
                break;

            case R_X86_64_NUM:
                type = "R_X86_64_NUM";
                break;
            
            default:
                break;
        }
        
        str_index = ELF64_R_SYM(rel_section[i].r_info);
        PRINT_RELA(i, rel_section[i].r_offset, rel_section[i].r_info, type, str_index, g_symtab.name[str_index]);
    }
    printf("\n");
}

/** 
 * @brief .relation information (.rela.*)
 * 
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_rela32(handle_t32 *h, char *section_name) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    int str_index;
    int rela_dyn_index;
    size_t count;
    Elf32_Rela *rela_dyn;
    int has_component = 0;
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            return -1;
        }

        if (!strcmp(name, section_name)) {
            rela_dyn_index = i;
            has_component = 1;
        }
    }

    if (!has_component) {
        WARNING("This file does not have a %s\n", section_name);
        return -1;
    }
    
    if (validated_offset(name, h->mem, h->mem + h->size)) {
        ERROR("Corrupt file format\n");
        return -1;
    }
    
    rela_dyn = (Elf32_Rela *)&h->mem[h->shdr[rela_dyn_index].sh_offset];
    count = h->shdr[rela_dyn_index].sh_size / sizeof(Elf32_Rela);
    INFO("Relocation section '%s' at offset 0x%x contains %d entries:\n", section_name, h->shdr[rela_dyn_index].sh_offset, count);
    PRINT_RELA_TITLE("Nr", "Offset", "Info", "Type", "Sym.Index", "Sym.Name + Addend");
    for (int i = 0; i < count; i++) {
        switch (ELF32_R_TYPE(rela_dyn[i].r_info))
        {
            case R_X86_64_NONE:
                type = "R_X86_64_NONE";
                break;

            case R_X86_64_64:
                type = "R_X86_64_64";
                break;

            case R_X86_64_PC32:
                type = "R_X86_64_PC32";
                break;

            case R_X86_64_GOT32:
                type = "R_X86_64_GOT32";
                break;

            case R_X86_64_PLT32:
                type = "R_X86_64_PLT32";
                break;

            case R_X86_64_COPY:
                type = "R_X86_64_COPY";
                break;

            case R_X86_64_GLOB_DAT:
                type = "R_X86_64_GLOB_DAT";
                break;

            case R_X86_64_JUMP_SLOT:
                type = "R_X86_64_JUMP_SLOT";
                break;

            case R_X86_64_RELATIVE:
                type = "R_X86_64_RELATIVE";
                break;

            case R_X86_64_GOTPCREL:
                type = "R_X86_64_GOTPCREL";
                break;

            case R_X86_64_32:
                type = "R_X86_64_32";
                break;

            case R_X86_64_32S:
                type = "R_X86_64_32S";
                break;

            case R_X86_64_16:
                type = "R_X86_64_16";
                break;

            case R_X86_64_PC16:
                type = "R_X86_64_PC16";
                break;

            case R_X86_64_8:
                type = "R_X86_64_8";
                break;

            case R_X86_64_PC8:
                type = "R_X86_64_PC8";
                break;

            case R_X86_64_DTPMOD64:
                type = "R_X86_64_DTPMOD64";
                break;

            case R_X86_64_DTPOFF64:
                type = "R_X86_64_DTPOFF64";
                break;

            case R_X86_64_TPOFF64:
                type = "R_X86_64_TPOFF64";
                break;

            case R_X86_64_TLSGD:
                type = "R_X86_64_TLSGD";
                break;

            case R_X86_64_TLSLD:
                type = "R_X86_64_TLSLD";
                break;

            case R_X86_64_DTPOFF32:
                type = "R_X86_64_DTPOFF32";
                break;

            case R_X86_64_GOTTPOFF:
                type = "R_X86_64_GOTTPOFF";
                break;

            case R_X86_64_TPOFF32:
                type = "R_X86_64_TPOFF32";
                break;

            case R_X86_64_PC64:
                type = "R_X86_64_PC64";
                break;

            case R_X86_64_GOTOFF64:
                type = "R_X86_64_GOTOFF64";
                break;

            case R_X86_64_GOTPC32:
                type = "R_X86_64_GOTPC32";
                break;

            case R_X86_64_GOT64:
                type = "R_X86_64_GOT64";
                break;

            case R_X86_64_GOTPCREL64:
                type = "R_X86_64_GOTPCREL64";
                break;

            case R_X86_64_GOTPC64:
                type = "R_X86_64_GOTPC64";
                break;

            case R_X86_64_GOTPLT64:
                type = "R_X86_64_GOTPLT64";
                break;

            case R_X86_64_PLTOFF64:
                type = "R_X86_64_PLTOFF64";
                break;

            case R_X86_64_SIZE32:
                type = "R_X86_64_SIZE32";
                break;

            case R_X86_64_SIZE64:
                type = "R_X86_64_SIZE64";
                break;

            case R_X86_64_GOTPC32_TLSDESC:
                type = "R_X86_64_GOTPC32_TLSDESC";
                break;

            case R_X86_64_TLSDESC_CALL:
                type = "R_X86_64_TLSDESC_CALL";
                break;

            case R_X86_64_TLSDESC:
                type = "R_X86_64_TLSDESC";
                break;

            case R_X86_64_IRELATIVE:
                type = "R_X86_64_IRELATIVE";
                break;

            case R_X86_64_RELATIVE64:
                type = "R_X86_64_RELATIVE64";
                break;

            case R_X86_64_GOTPCRELX:
                type = "R_X86_64_GOTPCRELX";
                break;

            case R_X86_64_REX_GOTPCRELX:
                type = "R_X86_64_REX_GOTPCRELX";
                break;

            case R_X86_64_NUM:
                type = "R_X86_64_NUM";
                break;
            
            default:
                break;
        }
        
        str_index = ELF32_R_SYM(rela_dyn[i].r_info);
        if (rela_dyn[i].r_addend >= 0)
            snprintf(name, STR_LENGTH, "%s + %d", g_dynsym.name[str_index], rela_dyn[i].r_addend);
        else
            snprintf(name, STR_LENGTH, "%s %d", g_dynsym.name[str_index], rela_dyn[i].r_addend);
        PRINT_RELA(i, rela_dyn[i].r_offset, rela_dyn[i].r_info, type, str_index, name);
    }
    printf("\n");
}

/** 
 * @brief .relation information
 * 
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_rela64(handle_t64 *h, char *section_name) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    int str_index;
    int rela_dyn_index;
    size_t count;
    Elf64_Rela *rela_dyn;
    int has_component = 0;
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            return -1;
        }

        if (!strcmp(name, section_name)) {
            rela_dyn_index = i;
            has_component = 1;
        }
    }

    if (!has_component) {
        WARNING("This file does not have a %s\n", section_name);
        return -1;
    }
    
    if (validated_offset(name, h->mem, h->mem + h->size)) {
        ERROR("Corrupt file format\n");
        return -1;
    }
    
    rela_dyn = (Elf64_Rela *)&h->mem[h->shdr[rela_dyn_index].sh_offset];
    count = h->shdr[rela_dyn_index].sh_size / sizeof(Elf64_Rela);
    INFO("Relocation section '%s' at offset 0x%x contains %d entries:\n", section_name, h->shdr[rela_dyn_index].sh_offset, count);
    PRINT_RELA_TITLE("Nr", "Offset", "Info", "Type", "Sym.Index", "Sym.Name + Addend");
    for (int i = 0; i < count; i++) {
        switch (ELF64_R_TYPE(rela_dyn[i].r_info))
        {
            case R_X86_64_NONE:
                type = "R_X86_64_NONE";
                break;

            case R_X86_64_64:
                type = "R_X86_64_64";
                break;

            case R_X86_64_PC32:
                type = "R_X86_64_PC32";
                break;

            case R_X86_64_GOT32:
                type = "R_X86_64_GOT32";
                break;

            case R_X86_64_PLT32:
                type = "R_X86_64_PLT32";
                break;

            case R_X86_64_COPY:
                type = "R_X86_64_COPY";
                break;

            case R_X86_64_GLOB_DAT:
                type = "R_X86_64_GLOB_DAT";
                break;

            case R_X86_64_JUMP_SLOT:
                type = "R_X86_64_JUMP_SLOT";
                break;

            case R_X86_64_RELATIVE:
                type = "R_X86_64_RELATIVE";
                break;

            case R_X86_64_GOTPCREL:
                type = "R_X86_64_GOTPCREL";
                break;

            case R_X86_64_32:
                type = "R_X86_64_32";
                break;

            case R_X86_64_32S:
                type = "R_X86_64_32S";
                break;

            case R_X86_64_16:
                type = "R_X86_64_16";
                break;

            case R_X86_64_PC16:
                type = "R_X86_64_PC16";
                break;

            case R_X86_64_8:
                type = "R_X86_64_8";
                break;

            case R_X86_64_PC8:
                type = "R_X86_64_PC8";
                break;

            case R_X86_64_DTPMOD64:
                type = "R_X86_64_DTPMOD64";
                break;

            case R_X86_64_DTPOFF64:
                type = "R_X86_64_DTPOFF64";
                break;

            case R_X86_64_TPOFF64:
                type = "R_X86_64_TPOFF64";
                break;

            case R_X86_64_TLSGD:
                type = "R_X86_64_TLSGD";
                break;

            case R_X86_64_TLSLD:
                type = "R_X86_64_TLSLD";
                break;

            case R_X86_64_DTPOFF32:
                type = "R_X86_64_DTPOFF32";
                break;

            case R_X86_64_GOTTPOFF:
                type = "R_X86_64_GOTTPOFF";
                break;

            case R_X86_64_TPOFF32:
                type = "R_X86_64_TPOFF32";
                break;

            case R_X86_64_PC64:
                type = "R_X86_64_PC64";
                break;

            case R_X86_64_GOTOFF64:
                type = "R_X86_64_GOTOFF64";
                break;

            case R_X86_64_GOTPC32:
                type = "R_X86_64_GOTPC32";
                break;

            case R_X86_64_GOT64:
                type = "R_X86_64_GOT64";
                break;

            case R_X86_64_GOTPCREL64:
                type = "R_X86_64_GOTPCREL64";
                break;

            case R_X86_64_GOTPC64:
                type = "R_X86_64_GOTPC64";
                break;

            case R_X86_64_GOTPLT64:
                type = "R_X86_64_GOTPLT64";
                break;

            case R_X86_64_PLTOFF64:
                type = "R_X86_64_PLTOFF64";
                break;

            case R_X86_64_SIZE32:
                type = "R_X86_64_SIZE32";
                break;

            case R_X86_64_SIZE64:
                type = "R_X86_64_SIZE64";
                break;

            case R_X86_64_GOTPC32_TLSDESC:
                type = "R_X86_64_GOTPC32_TLSDESC";
                break;

            case R_X86_64_TLSDESC_CALL:
                type = "R_X86_64_TLSDESC_CALL";
                break;

            case R_X86_64_TLSDESC:
                type = "R_X86_64_TLSDESC";
                break;

            case R_X86_64_IRELATIVE:
                type = "R_X86_64_IRELATIVE";
                break;

            case R_X86_64_RELATIVE64:
                type = "R_X86_64_RELATIVE64";
                break;

            case R_X86_64_GOTPCRELX:
                type = "R_X86_64_GOTPCRELX";
                break;

            case R_X86_64_REX_GOTPCRELX:
                type = "R_X86_64_REX_GOTPCRELX";
                break;

            case R_X86_64_NUM:
                type = "R_X86_64_NUM";
                break;
            
            default:
                break;
        }
        
        str_index = ELF64_R_SYM(rela_dyn[i].r_info);
        if (rela_dyn[i].r_addend >= 0)
            snprintf(name, STR_LENGTH, "%s + %d", g_dynsym.name[str_index], rela_dyn[i].r_addend);
        else
            snprintf(name, STR_LENGTH, "%s %d", g_dynsym.name[str_index], rela_dyn[i].r_addend);
        PRINT_RELA(i, rela_dyn[i].r_offset, rela_dyn[i].r_info, type, str_index, name);
    }
    printf("\n");
}

/** 
 * @brief 显示ELF相关节包含的指针
 * display .init_array .finit_array .ctors .dtors	
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_pointer32(handle_t32 *h, int num, ...) {
    char *name = NULL;
    int index[10];
    int strtab_index = 0;
    size_t count = 0;

    for (int i = 0; i < 10; i++) {
        index[i] = 0;
    }

    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            return -1;
        }

        va_list args;                       // 定义一个 va_list 类型的变量
        va_start(args, num);                // 初始化可变参数列表

        for (int j = 0; j < num; j++) {
            char *section_name = va_arg(args, char *); // 从可变参数列表中获取参数值
            if (!strcmp(name, section_name)) {
                index[j] = i;
            }
        }

        va_end(args);                       // 结束可变参数列表的使用

        // 判断是否存在符号表
        // determine whether there is a symbol table
        if (!strcmp(name, ".strtab")) {
            strtab_index = i;
        }
    }

    va_list args;
    va_start(args, num);

    for (int j = 0; j < num; j++) {
        char *section_name = va_arg(args, char *);
        if (index[j] == 0) {
            WARNING("This file does not have a %s\n", section_name);
        } else {
            uint32_t offset = h->shdr[index[j]].sh_offset;
            size_t size = h->shdr[index[j]].sh_size;
            uint32_t *addr = h->mem + offset;
            int count = size / 4;
            INFO("%s section at offset 0x%x contains %d pointers:\n", section_name, offset, count);
            PRINT_POINTER32_TITLE("Nr", "Pointer", "Symbol");
            for (int i = 0; i < count; i++) {
                if (strtab_index) {
                    int find_sym = 0;
                    for (int k = 0; k < g_symtab.count; k++) {
                        if (addr[i] == g_symtab.value[k]) {
                            PRINT_POINTER32(i, addr[i], g_symtab.name[k]);
                            find_sym = 1;
                            break;
                        }
                    }
                    if (!find_sym) {
                        PRINT_POINTER32(i, addr[i], "0");
                    }
                } else {
                    PRINT_POINTER32(i, addr[i], "0");
                }
            }
        }
    }

    va_end(args);
    
    printf("\n");
}

/** 
 * @brief 显示ELF相关节包含的指针
 * display .init_array .finit_array .ctors .dtors	
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_pointer64(handle_t64 *h, int num, ...) {
    char *name = NULL;
    int index[10];
    int strtab_index = 0;
    size_t count = 0;

    for (int i = 0; i < 10; i++) {
        index[i] = 0;
    }

    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            return -1;
        }

        va_list args;                       // 定义一个 va_list 类型的变量
        va_start(args, num);                // 初始化可变参数列表

        for (int j = 0; j < num; j++) {
            char *section_name = va_arg(args, char *); // 从可变参数列表中获取参数值
            if (!strcmp(name, section_name)) {
                index[j] = i;
            }
        }

        va_end(args);                       // 结束可变参数列表的使用

        // 判断是否存在符号表
        // determine whether there is a symbol table
        if (!strcmp(name, ".strtab")) {
            strtab_index = i;
        }
    }

    va_list args;
    va_start(args, num);

    for (int j = 0; j < num; j++) {
        char *section_name = va_arg(args, char *);
        if (index[j] == 0) {
            WARNING("This file does not have a %s\n", section_name);
        } else {
            uint64_t offset = h->shdr[index[j]].sh_offset;
            size_t size = h->shdr[index[j]].sh_size;
            uint64_t *addr = h->mem + offset;
            int count = size / 4;
            INFO("%s section at offset 0x%x contains %d pointers:\n", section_name, offset, count);
            PRINT_POINTER64_TITLE("Nr", "Pointer", "Symbol");
            for (int i = 0; i < count; i++) {
                if (strtab_index) {
                    int find_sym = 0;
                    for (int k = 0; k < g_symtab.count; k++) {
                        if (addr[i] == g_symtab.value[k]) {
                            PRINT_POINTER64(i, addr[i], g_symtab.name[k]);
                            find_sym = 1;
                            break;
                        }
                    }
                    if (!find_sym) {
                        PRINT_POINTER64(i, addr[i], "0");
                    }
                } else {
                    PRINT_POINTER64(i, addr[i], "0");
                }
            }
        }
    }

    va_end(args);
    
    printf("\n");
}
