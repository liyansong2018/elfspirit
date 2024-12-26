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
#include "rel.h"

extern struct MyStr g_dynsym;
extern parser_opt_t po;

/**
 * @brief 初始化elf文件，将elf文件转化为elf结构体
 * initialize the elf file and convert it into an elf structure
 * @param elf elf file name
 * @return error code {-1:error, 0:success}
 */
int init_elf(char *elf, handle_t32 *h32, handle_t64 *h64) {
    int fd = -1;
    struct stat st;
    uint8_t *elf_map = NULL;

    memset(h32, 0, sizeof(handle_t32));
    memset(h64, 0, sizeof(handle_t64));

    if (MODE == -1) {
        return -1;
    }

    fd = open(elf, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        h32->mem = elf_map;
        h32->ehdr = (Elf32_Ehdr *)h32->mem;
        h32->shdr = (Elf32_Shdr *)&h32->mem[h32->ehdr->e_shoff];
        h32->phdr = (Elf32_Phdr *)&h32->mem[h32->ehdr->e_phoff];
        h32->shstrtab = (Elf32_Shdr *)&h32->shdr[h32->ehdr->e_shstrndx];
        h32->size = st.st_size;
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        h64->mem = elf_map;
        h64->ehdr = (Elf64_Ehdr *)h64->mem;
        h64->shdr = (Elf64_Shdr *)&h64->mem[h64->ehdr->e_shoff];
        h64->phdr = (Elf64_Phdr *)&h64->mem[h64->ehdr->e_phoff];
        h64->shstrtab = (Elf64_Shdr *)&h64->shdr[h64->ehdr->e_shstrndx];
        h64->size = st.st_size;
    }

    /* init symbol string table*/
    parse(elf, &po, 0);
    return 0;
}

int finit_elf(handle_t32 *h32, handle_t64 *h64) {
    close(h32->fd);
    munmap(h32->mem, h32->size);
    close(h64->fd);
    munmap(h64->mem, h64->size);
}

/**
 * @brief 根据节名，获取节的下标
 * obtain the index of the section based on its name
 * @param h elf struct
 * @param sec_name section name, such as .rela.plt
 * @return section index {-1:error}
 */
int get_sec_index32(handle_t32 *h, char *sec_name) {
    void *tmp_name = NULL;
    h->sec_index = -1;
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        tmp_name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(tmp_name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            return -1;
        }
        if (!strcmp(tmp_name, sec_name)) {
            h->sec_index = i;
            h->sec_size = h->shdr[i].sh_size;
            break;
        } 
    }
    return h->sec_index;
}

int get_sec_index64(handle_t64 *h, char *sec_name) {
    void *tmp_name = NULL;
    h->sec_index = -1;
    for (int i = 0; i < h->ehdr->e_shnum; i++) {
        tmp_name = h->mem + h->shstrtab->sh_offset + h->shdr[i].sh_name;
        if (validated_offset(tmp_name, h->mem, h->mem + h->size)) {
            ERROR("Corrupt file format\n");
            return -1;
        }
        if (!strcmp(tmp_name, sec_name)) {
            h->sec_index = i;
            h->sec_size = h->shdr[i].sh_size;
            break;
        } 
    }
    return h->sec_index;
}

/**
 * @brief 根据节名，获取relocation
 * obtain .rel section based on its name
 * @param h elf struct
 * @param sec_name section name, such as .rel.plt
 * @param rel output .rel content
 * @return section index {-1:error}
 */
int get_rel32(handle_t32 *h, char *sec_name, Elf32_Rel **rel) {
    if (get_sec_index32(h, sec_name) < 0) {
        return -1;
    }
    *rel = h->mem + h->shdr[h->sec_index].sh_offset;
    return 0;
}

int get_rel64(handle_t64 *h, char *sec_name, Elf64_Rel **rel) {
    if (get_sec_index64(h, sec_name) < 0) {
        return -1;
    }
    *rel = h->mem + h->shdr[h->sec_index].sh_offset;
    return 0;
}

/**
 * @brief 根据节名，获取relocation
 * obtain .rela section based on its name
 * @param h elf struct
 * @param sec_name section name, such as .rela.plt
 * @param rela output .rel content
 * @return section index {-1:error}
 */
int get_rela32(handle_t32 *h, char *sec_name, Elf32_Rela **rela) {
    if (get_sec_index32(h, sec_name) < 0) {
        return -1;
    }
    *rela = h->mem + h->shdr[h->sec_index].sh_offset;
    return 0;
}

int get_rela64(handle_t64 *h, char *sec_name, Elf64_Rela **rela) {
    if (get_sec_index64(h, sec_name) < 0) {
        return -1;
    }
    *rela = h->mem + h->shdr[h->sec_index].sh_offset;
    return 0;
}

// rel.plt, .rela.plt, .rel.dyn, .rela.dyn, .rel.android, .rela.android
/**
 * @brief 得到重定位符号的偏移（其实是指地址，而非文件偏移）
 * obtain the offset of the relocation symbol (actually referring to the address, not the file offset)
 * @param h elf file struct
 * @param sec_name section name
 * @return item address {-1:error, 0:success}
 */
uint32_t get_rel32_addr(handle_t32 *h, char *sec_name, int index) {
    Elf32_Rel *rel;
    if (get_rel32(h, sec_name, &rel)) {
        return -1;
    }
    if (index > h->sec_size / sizeof(Elf32_Rel)) {
        return -1;
    }
    return rel[index].r_offset;
}

uint64_t get_rel64_addr(handle_t64 *h, char *sec_name, int index) {
    Elf64_Rel *rel;
    if (get_rel64(h, sec_name, &rel)) {
        return -1;
    }
    if (index > h->sec_size / sizeof(Elf64_Rel)) {
        return -1;
    }
    return rel[index].r_offset;
}

/**
 * @brief 得到重定位符号的偏移（其实是指地址，而非文件偏移）
 * obtain the offset of the relocation symbol (actually referring to the address, not the file offset)
 * @param h elf file struct
 * @param sec_name section name
 * @return item address {-1:error, 0:success}
 */
uint32_t get_rela32_addr(handle_t32 *h, char *sec_name, int index) {
    Elf32_Rela *rela;
    if (get_rela32(h, sec_name, &rela)) {
        return -1;
    }
    if (index > h->sec_size / sizeof(Elf32_Rela)) {
        return -1;
    }
    return rela[index].r_offset;
}

uint64_t get_rela64_addr(handle_t64 *h, char *sec_name, int index) {
    Elf64_Rela *rela;
    if (get_rela64(h, sec_name, &rela)) {
        return -1;
    }
    if (index > h->sec_size / sizeof(Elf64_Rela)) {
        return -1;
    }
    return rela[index].r_offset;
}

/**
 * @brief 得到重定位符号的符号名
 * obtain the name of the relocation symbol
 * @param h elf file struct
 * @param sec_name section name
 * @param index .rel section item index
 * @param name symbol name
 * @return error code {-1:error, 0:success}
 */
int get_rel32_name(handle_t32 *h, char *sec_name, int index, char **name) {
    Elf32_Rel *rel;
    if (get_rel32(h, sec_name, &rel)) {
        return -1;
    }
    if (index > h->sec_size / sizeof(Elf32_Rel)) {
        return -1;
    }
    int str_index = ELF32_R_SYM(rel[index].r_info);
    *name = &g_dynsym.name[str_index];
    return 0;
}

int get_rel64_name(handle_t64 *h, char *sec_name, int index, char **name) {
    Elf64_Rel *rel;
    if (get_rel64(h, sec_name, &rel)) {
        return -1;
    }
    if (index > h->sec_size / sizeof(Elf64_Rel)) {
        return -1;
    }
    int str_index = ELF64_R_SYM(rel[index].r_info);
    *name = &g_dynsym.name[str_index];
    return 0;
}

int get_rela32_name(handle_t32 *h, char *sec_name, int index, char **name) {
    Elf32_Rela *rela;
    if (get_rela32(h, sec_name, &rela)) {
        return -1;
    }
    if (index > h->sec_size / sizeof(Elf64_Rel)) {
        return -1;
    }
    int str_index = ELF32_R_SYM(rela[index].r_info);
    *name = &g_dynsym.name[str_index];
    return 0;
}

int get_rela64_name(handle_t64 *h, char *sec_name, int index, char **name) {
    Elf64_Rela *rela;
    if (get_rela64(h, sec_name, &rela)) {
        return -1;
    }
    if (index > h->sec_size / sizeof(Elf64_Rel)) {
        return -1;
    }
    int str_index = ELF64_R_SYM(rela[index].r_info);
    *name = &g_dynsym.name[str_index];
    return 0;
}

/**
 * @brief 得到重定位符号的文件偏移
 * obtain the file offset of the relocation symbol
 * @param h elf file struct
 * @param sec_name section name
 * @return item file offset {-1:error, 0:success}
 */
uint32_t get_rel32_offset(handle_t32 *h, char *sec_name, int index) {
    uint32_t addr = get_rel32_addr(h, sec_name, index);
    int ret = get_sec_index32(h, ".got.plt");
    if (ret < 0) {
        return -1;
    }
    int diff = h->shdr[h->sec_index].sh_addr - h->shdr[h->sec_index].sh_offset;
    return addr - diff;
}

uint64_t get_rel64_offset(handle_t64 *h, char *sec_name, int index) {
    uint64_t addr = get_rel64_addr(h, sec_name, index);
    int ret = get_sec_index64(h, ".got.plt");
    if (ret < 0) {
        return -1;
    }
    int diff = h->shdr[h->sec_index].sh_addr - h->shdr[h->sec_index].sh_offset;
    return addr - diff;
}

uint32_t get_rela32_offset(handle_t32 *h, char *sec_name, int index) {
    uint32_t addr = get_rela32_addr(h, sec_name, index);
    int ret = get_sec_index32(h, ".got.plt");
    if (ret < 0) {
        return -1;
    }
    int diff = h->shdr[h->sec_index].sh_addr - h->shdr[h->sec_index].sh_offset;
    return addr - diff;
}

uint64_t get_rela64_offset(handle_t64 *h, char *sec_name, int index) {
    uint64_t addr = get_rela64_addr(h, sec_name, index);
    int ret = get_sec_index64(h, ".got.plt");
    if (ret < 0) {
        return -1;
    }
    int diff = h->shdr[h->sec_index].sh_addr - h->shdr[h->sec_index].sh_offset;
    return addr - diff;
}

// /**
//  * @brief 根据下标获取某一项重定位
//  * retrieve a relocation based on the index
//  * @param elf_name elf name
//  * @param section_name section name, such as .rela.plt
//  * @param idnex relocation item index
//  * @return all relocation size
//  */
// int get_rel(char *elf_name, char *section_name, int index, char *out_relocation) {
//     int fd;
//     struct stat st;
//     uint8_t *elf_map;
//     uint8_t *tmp_sec_name;
//     size_t size = 0;

//     fd = open(elf_name, O_RDWR);
//     if (fd < 0) {
//         perror("open");
//         return -1;
//     }

//     if (fstat(fd, &st) < 0) {
//         perror("fstat");
//         return -1;
//     }

//     elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
//     if (elf_map == MAP_FAILED) {
//         perror("mmap");
//         return -1;
//     }
    
//     /* 32bit */
//     if (MODE == ELFCLASS32) {
//         Elf32_Ehdr *ehdr;
//         Elf32_Shdr *shdr;
//         Elf32_Shdr shstrtab;
//         Elf32_Rel *rel;
//         Elf32_Rela *rela;

//         ehdr = (Elf32_Ehdr *)elf_map;
//         shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
//         shstrtab = shdr[ehdr->e_shstrndx];

//         for (int i = 0; i < ehdr->e_shnum; i++) {
//             tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
//             if (!strcmp(section_name, tmp_sec_name)) {
//                 rel = (Elf32_Rel *)(elf_map + shdr[i].sh_offset);
//                 rela = (Elf32_Rela *)(elf_map + shdr[i].sh_offset);
//                 size = shdr[i].sh_size;
//                 break;
//             }
//         }

//         if (!compare_firstN_chars(section_name, ".rela", 5)) {
//             memcpy(out_relocation, &rela[index], sizeof(Elf32_Rela));
//         } else if (!compare_firstN_chars(section_name, ".rel.", 5)) {
//             memcpy(out_relocation, &rel[index], sizeof(Elf32_Rel));
//         }
//     }

//     /* 64bit */
//     if (MODE == ELFCLASS64) {
//     }

//     close(fd);
//     munmap(elf_map, st.st_size);
//     return size;
// }

// /**
//  * @brief 重定位节的项目的地址
//  * get relocation item address
//  * @param elf_name elf name
//  * @param section_name section name, such as .rela.plt
//  * @return item address/offset
//  */
// int get_rel_addr(char *elf_name, char *section_name, int index) {
//     size_t size = 0;
//     if (MODE == ELFCLASS32) {
//         if (!compare_firstN_chars(section_name, ".rela", 5)) {
//             Elf32_Rela rela;
//             size = get_rel(elf_name, section_name, index, &rela);
//             if (!size) {
//                 return -1;
//             }
//             return rela.r_offset;
//         } else if (!compare_firstN_chars(section_name, ".rel.", 5)) {
//             Elf32_Rel rel;
//             size = get_rel(elf_name, section_name, index, &rel);
//             if (!size) {
//                 return -1;
//             }
//             return rel.r_offset;
//         }
//     } else if (MODE == ELFCLASS64) {
//         if (!compare_firstN_chars(section_name, ".rela", 5)) {
//             Elf64_Rela rela;
//             size = get_rel(elf_name, section_name, index, &rela);
//             if (!size) {
//                 return -1;
//             }
//             return rela.r_offset;
//         } else if (!compare_firstN_chars(section_name, ".rel.", 5)) {
//             Elf64_Rel rel;
//             size = get_rel(elf_name, section_name, index, &rel);
//             if (!size) {
//                 return -1;
//             }
//             return rel.r_offset;
//         }
//     }
// }