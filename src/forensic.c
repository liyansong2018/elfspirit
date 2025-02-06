#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include "common.h"
#include "section.h"

/**
 * @brief 检查hook外部函数
 * chekc hook function by .got.plt
 * @param elf_name elf file name
 * @param addr start address(.plt)
 * @param size section size(.plt)
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_hook(char *elf_name, uint64_t addr,size_t size) {
    uint64_t offset = 0;
    int ret = -1;

    char *name;
    handle_t32 h32;
    handle_t64 h64;
    ret = init_elf(elf_name, &h32, &h64);
    if (ret < 0) {
        ERROR("init elf error\n");
        goto ERR_EXIT;
    }

    /* attention: The 32-bit program has not been tested! */
    if (MODE == ELFCLASS32) {
        h32.sec_size = sizeof(Elf32_Rel);  // init
        for (int i = 0; i < h32.sec_size / sizeof(Elf32_Rel); i++) {
            offset = get_rel32_offset(&h32, ".rel.plt", i);
            if (offset == -1) {
                goto ERR_EXIT;
                break;
            }
            uint32_t *p = (uint32_t *)(h32.mem + offset);
            DEBUG("0x%x, 0x%x\n", offset, *p);
            if (*p < addr || *p >= addr + size) {
                goto FAILED;
            }
        }
    }

    if (MODE == ELFCLASS64) {
        h64.sec_size = sizeof(Elf64_Rela);  // init
        for (int i = 0; i < h64.sec_size / sizeof(Elf64_Rela); i++) {
            offset = get_rela64_offset(&h64, ".rela.plt", i);
            if (offset == -1) {
                goto ERR_EXIT;
                break;
            }
            uint64_t *p = (uint64_t *)(h64.mem + offset);
            DEBUG("0x%x, 0x%x\n", offset, *p);
            if (*p < addr || *p >= addr + size) {
                goto FAILED;
            }
        }
    }
    
    finit_elf(&h32, &h64);
    return 0;
ERR_EXIT:
    return -1;
FAILED:
    finit_elf(&h32, &h64);
    return 1;
}

/**
 * @brief 检查load
 * chekc load segment flags
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_load_flags(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    int count = 0;

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
                // flags:E
                if (phdr[i].p_flags & 0x1) {
                    count++;
                }
            }
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
        Elf64_Phdr *phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // flags:E
                if (phdr[i].p_flags & 0x1) {
                    count++;
                }
            }
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    DEBUG("executable segment count: %d\n", count);
    if (count > 1) {
        return 1;
    } else if (count == 1) {
        return 0;
    } else if (count == 0) {
        return -1;
    } 
}

/**
 * @brief 检查段是否连续
 * check if the load segments are continuous
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_load_continuity(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    int last = 0;
    int current = 0;
    int has_first = 0;

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
                if (!has_first) {
                    has_first = 1;
                    last = i;
                    continue;
                }
                
                current = i;
                if (current - last != 1) {
                    close(fd);
                    munmap(elf_map, st.st_size);
                    return 1;
                }
                last = i;
            }
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
        Elf64_Phdr *phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                if (!has_first) {
                    has_first = 1;
                    last = i;
                    continue;
                }
                
                current = i;
                if (current - last != 1) {
                    close(fd);
                    munmap(elf_map, st.st_size);
                    return 1;
                }
                last = i;
            }
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

/**
 * @brief 检查DT_NEEDED是否连续
 * check if the DT_NEEDED so are continuous
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_needed_continuity(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    int last = 0;
    int current = 0;
    int has_first = 0;
    int ret = 0;

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
        Elf32_Dyn *dyn = NULL;
        uint32_t dyn_c;
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                dyn = elf_map + phdr[i].p_offset;
                dyn_c = phdr[i].p_filesz / sizeof(Elf32_Dyn);
                break;
            }
        }
        if (!dyn) ret = -1;
        else {
            for (int i = 0; i < dyn_c; i++) {
                if (dyn[i].d_tag == DT_NEEDED) {
                    if (!has_first) {
                        has_first = 1;
                        last = i;
                        continue;
                    }
                    
                    current = i;
                    if (current - last != 1) {
                        ret = 1;
                        break;
                    }
                    last = i;
                }
            }
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
        Elf64_Phdr *phdr = (Elf64_Phdr *)&elf_map[ehdr->e_phoff];
        Elf64_Dyn *dyn = NULL;
        uint64_t dyn_c;
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                dyn = elf_map + phdr[i].p_offset;
                dyn_c = phdr[i].p_filesz / sizeof(Elf64_Dyn);
                break;
            }
        }
        if (!dyn) ret = -1;
        else {
            for (int i = 0; i < dyn_c; i++) {
                if (dyn[i].d_tag == DT_NEEDED) {
                    if (!has_first) {
                        has_first = 1;
                        last = i;
                        continue;
                    }
                    
                    current = i;
                    if (current - last != 1) {
                        ret = 1;
                        break;
                    }
                    last = i;
                }
            }
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return ret;
}

/**
 * @brief 检查elf文件是否合法
 * check if the elf file is legal
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess}
 */
int checksec(char *elf_name) {
    printf("|--------------------------------------------------------------------------|\n");
    printf("|%-20s|%1s| %-50s|\n", "checkpoint", "s", "description");
    printf("|--------------------------------------------------------------------------|\n");
    /* check entry */
    uint64_t entry = get_entry(elf_name);
    uint64_t addr = get_section_addr(elf_name, ".text");
    size_t size = get_section_size(elf_name, ".text");
    if (entry == addr) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "entry point", "✓", "normal");
    } else if (entry > addr && entry < addr + size) {
        CHECK_WARNING("|%-20s|%1s| %-50s|\n", "entry point", "-", "the entry point IS inside the .TEXT section");
    } else {
        CHECK_ERROR("|%-20s|%1s| %-50s|\n","entry point", "✗", "the entry point is NOT inside the .TEXT section");
    }

    /* check plt/got hook (lazy bind) */
    addr = get_section_addr(elf_name, ".plt");
    size = get_section_size(elf_name, ".plt");
    int ret = check_hook(elf_name, addr, size);
    if (ret == 0) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "hook(.got.plt)", "✓", "normal");
    } else if (ret == 1) {
        CHECK_ERROR("|%-20s|%1s| %-50s|\n", "hook(.got.plt)", "✗", ".got.plt hook is detected");
    } else if (ret == -1) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "hook(.got.plt)", "-", "na(bind now)");
    }

    /* check load segment permission */
    ret = check_load_flags(elf_name);
    if (ret == 0) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "load flags", "✓", "normal");
    } else if (ret == 1) {
        CHECK_ERROR("|%-20s|%1s| %-50s|\n", "load flags", "✗", "more than one executable segment");
    } else if (ret == -1) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "load flags", "-", "na(no executable elf file)");
    }

    /* check segment continuity */
    ret = check_load_continuity(elf_name);
    if (ret == 0) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "load continuity", "✓", "normal");
    } else if (ret == 1) {
        CHECK_ERROR("|%-20s|%1s| %-50s|", "load continuity", "✗", "load segments are NOT continuous");
    } else if (ret == -1) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "load continuity", "-", "na");
    }

    /* check DLL injection */
    ret = check_needed_continuity(elf_name);
    if (ret == 0) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "DT_NEEDED continuity", "✓", "normal");
    } else if (ret == 1) {
        CHECK_ERROR("|%-20s|%1s| %-50s|\n", "DT_NEEDED continuity", "✗", "DT_NEEDED libraries are NOT continuous");
    } else if (ret == -1) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", "DT_NEEDED continuity", "-", "na(static elf)");
    }

    printf("|--------------------------------------------------------------------------|\n");
    return 0;
}