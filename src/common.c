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

int MODE;
int ARCH;

/**
 * @description: Judge whether the memory address is legal
 * @param {uint64_t} addr
 * @param {uint64_t} start
 * @param {uint64_t} end
 * @return {*}
 */
int validated_offset(uint64_t addr, uint64_t start, uint64_t end){
    return addr <= end && addr >= start? 0:-1;
}

/**
 * @description: get name from path. (从路径中得到文件名)
 * @param {char} *file
 * @param {char} *file_name
 * @return {*}
 */
void get_name(char *file, char *file_name) {
    char ch = '\/';
    strcpy(file_name, strrchr(file, ch) + 1);
}

/**
 * @description: get path without name from file path. (从文件路径中得到不包含文件名的路径)
 * @param {char} *file
 * @param {char} *file_path
 * @return {*}
 */
void get_path(char *file, char *file_path) {
    char ch = '\/';
    memcpy(file_path, file, strrchr(file, ch) + 1 - file);
}

/**
 * @description: char to int. (将字符转换为数值)
 * @param {char} ch
 * @return {*}
 */
int c2i(char ch) {
    if(isdigit(ch))
        return ch - 48;
 
    if( ch < 'A' || (ch > 'F' && ch < 'a') || ch > 'z' )
        return -1;
 
    if(isalpha(ch))
        return isupper(ch) ? ch - 55 : ch - 87;

    return -1;
} 

/**
 * @description: hex string to int. (将十六进制字符串转换为整型(int)数值)
 * @param {char} *hex
 * @return {*}
 */
unsigned int hex2int(char *hex) {  
    int len;
    int num = 0;
    int temp;
    int bits;
    int i;

    if (strlen(hex) <= 2) {
        return -1;
    }

    char *new_hex = hex + 2;
    len = strlen(new_hex);

    for (i = 0, temp = 0; i < len; i++, temp = 0)  
    {
        temp = c2i(*(new_hex + i));  
        bits = (len - i - 1) * 4;  
        temp = temp << bits;  
        num = num | temp;  
    }
    
    return num;  
}

/**
 * @description: String reverse. (字符串逆序)
 * @param {char} *str
 * @return {*}
 */
char *strrev(char *str)
{
    char *p1, *p2;

    if (! str || ! *str)
        return str;
    for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2)
    {
        *p1 ^= *p2;
        *p2 ^= *p1;
        *p1 ^= *p2;
    }
    return str;
}

/**
 * @description: String reverse from start to end. (指定位置的字符串逆序)
 * @param {char} *str
 * @param {int} offset
 * @param {int} length
 * @return {*}
 */
char *str_reverse(char *str, int offset, int length) {
    char tmp[PATH_LENGTH];
    memset(tmp, 0, PATH_LENGTH);
    memcpy(tmp, &str[offset], length);
    return strrev(tmp);
}

/**
 * @description: Convert hex to printable string. (将十六进制转化为可打印的字符串)
 * @param {unsigned int} hex
 * @param {char} *ret
 * @param {unsigned int} len string length
 * @return {*}
 */
int hex2str(unsigned int hex, char *ret, unsigned int len) {
    for (int i = 0; i < len; i++) {
        ret[i] = (hex >> 8 * i) & 0xff;
    }
    return 0;
}

/**
 * @brief Compare string
 * 
 * @param str1 
 * @param str2 
 * @param n 
 * @return int 
 */
int compare_firstN_chars(const char *str1, const char *str2, int n) {
    // 检查字符串长度是否小于n，如果是，则返回0（不相同）
    if (strlen(str1) < n || strlen(str2) < n) {
        return 0;
    }

    // 比较两个字符串的前n位是否相同
    return strncmp(str1, str2, n) == 0;
}

/**
 * @brief 计算一个地址的4K对齐地址
 * align 4k address
 * @param address input address
 * @return uint64_t output 4k address
 */
uint64_t align_to_4k(uint64_t address) {
    return ((address + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
}

/**
 * @description: Determine whether elf is in 32-bit mode or 64-bit mode. (判断elf是32位还是64位)
 * @param {char} *elf_name
 * @return {*}
 */
int get_elf_class(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    int mode;

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

    if (elf_map[0] != 0x7f || strncmp(&elf_map[1], "ELF", 3)) {
        ERROR("%s is not an ELF file\n", elf_name);
        return -1;
    }

    /* EI_CLASS */
    switch (elf_map[4]) {
        case ELFCLASS32:
            mode = ELFCLASS32;
            break;
        case ELFCLASS64:
            mode = ELFCLASS64;
            break;
        default:
            WARNING("Invalid class\n");
            return -1;
    }

    munmap(elf_map, st.st_size);
    close(fd);

    return mode;
}

/**
 * @description: Get elf architecture, such as EM_386, EM_X86_64, EM_ARM and EM_MIPS. (ELF文件架构)
 * @param {char} *elf_name
 * @return {*}
 */
int get_elf_machine(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    Elf32_Ehdr *ehdr;
    int arch;

    fd = open(elf_name, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        ERROR("fstat\n");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        ERROR("mmap\n");
        return -1;
    }

    /* e_machine */
    ehdr = (Elf32_Ehdr *)elf_map;    
    arch = ehdr->e_machine;
    munmap(elf_map, st.st_size);
    close(fd);

    return arch;
}

/**
 * @description: Judge whether the address is the starting address of the section (判断地址是否为section起始地址)
 * @param {char} *elf_name
 * @param {int} offset
 * @return {*}
 */
int is_sec_addr(char *elf_name, int offset) {
    int fd;
    int mode;
    struct stat st;
    uint8_t *elf_map;

    fd = open(elf_name, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        ERROR("fstat\n");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        ERROR("mmap\n");
        return -1;
    }
    
    mode = get_elf_class(elf_name);
    if (mode == ELFCLASS32) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
        Elf32_Shdr *shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        for (int i = 0; i < ehdr->e_shnum; i++) {
            if(shdr[i].sh_offset == offset) {
                munmap(elf_map, st.st_size);
                close(fd);
                return i;
            }
        }
    } else if (mode == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
        Elf64_Shdr *shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        for (int i = 0; i < ehdr->e_shnum; i++) {
            if(shdr[i].sh_offset == offset) {
                munmap(elf_map, st.st_size);
                close(fd);
                return i;
            }
        }
    }

    munmap(elf_map, st.st_size);
    close(fd);

    return -1;
}

/**
 * @description: Create new file to store changes
 * @param {char} *elf_name original file name
 * @param {char} *elf_map
 * @param {uint32_t} map_size
 * @param {uint32_t} is_new
 * @return {*}
 */
int create_file(char *elf_name, char *elf_map, uint32_t map_size, uint32_t is_new) {
    /* new file */
    char new_name[PATH_LENGTH_NEW];
    memset(new_name, 0, PATH_LENGTH_NEW);
    if (is_new) 
        snprintf(new_name, PATH_LENGTH_NEW, "%s.new", elf_name);
    else
        strncpy(new_name, elf_name, PATH_LENGTH_NEW);
        
    int fd_new = open(new_name, O_RDWR|O_CREAT|O_TRUNC, 0777);
    if (fd_new < 0) {
        ERROR("open fd_new\n");
        return -1;
    }
    
    write(fd_new, elf_map, map_size);  
    INFO("create %s\n", new_name);
    close(fd_new);
    return 0;
}

/**
 * @description: Create json object from json file
 * @param {char} *name original json file name
 * @return {*}
 */
cJSON *get_json_object(char *name) {
    FILE *fp;
    int len;
    char *content;
    cJSON *cJsonObject;

    fp = fopen(name, "rb");
    if (fp <= 0) {
        perror("fopen");
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    content = (char *)malloc(len + 1);      // len + 1, fix off-by-one
    memset(content, 0, len + 1);        
    fread(content, 1, len, fp);
    cJsonObject = cJSON_Parse(content);
    fclose(fp);
    free(content);
    return cJsonObject;
}

/**
 * @brief Extract binary fragments from the target file
 * 
 * @param input_file original file name
 * @param offset start address
 * @param size end address(size)
 */
void extract_fragment(const char *input_file, long offset, size_t size) {
    FILE *input_fp = fopen(input_file, "rb");
    if (input_fp == NULL) {
        perror("Error opening input file");
        return;
    }

    // 设置文件指针偏移量
    fseek(input_fp, offset, SEEK_SET);

    // 读取指定大小的数据
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (buffer == NULL) {
        perror("Memory allocation error");
        fclose(input_fp);
        return;
    }

    fread(buffer, 1, size, input_fp);
    for (int i = 0; i < size; i++) {
        printf("\\x%02x", buffer[i]);
    }
    printf("\n");

    // 关闭输入文件
    fclose(input_fp);

    // 写入数据到一个新文件
    FILE *output_fp = fopen("/tmp/elfspirt_out.bin", "wb");
    if (output_fp == NULL) {
        perror("Error creating output file");
        free(buffer);
        return;
    }

    fwrite(buffer, 1, size, output_fp);
    printf("write to %s\n", "/tmp/elfspirt_out.bin");

    // 关闭输出文件
    fclose(output_fp);

    free(buffer);
}

/**
 * @brief Get the section content
 * 
 * @param elf_name original file name
 * @param section_name input argument: section name
 * @param section_info output argument: section content
 * @return error code {-1:error,0:sucess}
 */
int get_section(char *elf_name, char *section_name, char *section_info) {
    MODE = get_elf_class(elf_name);
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *name;
    int flag = 0;

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
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Shdr shstrtab;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (validated_offset(name, elf_map, elf_map + st.st_size)) {
                ERROR("Corrupt file format\n");
                goto ERR_EXIT;
            }
            if (!strcmp(name, section_name)) {
                flag = 1;
                memcpy(section_info, &shdr[i], sizeof(Elf32_Shdr));
                break;
            }
        }
    }

    /* 64bit */
    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (validated_offset(name, elf_map, elf_map + st.st_size)) {
                ERROR("Corrupt file format\n");
                goto ERR_EXIT;
            }
            if (!strcmp(name, section_name)) {
                flag = 1;
                memcpy(section_info, &shdr[i], sizeof(Elf32_Shdr));
                break;
            }
        }
    }

    else {
        ERROR("Invalid ELF class");
        goto ERR_EXIT;
    }

    if (!flag) {
        ERROR("This file does not have %s\n", section_name);
        goto ERR_EXIT;
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;

ERR_EXIT:
    close(fd);
    munmap(elf_map, st.st_size);
    return -1;
};

/**
 * @brief Get the section address
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section address
 */
int get_section_addr(char *elf_name, char *section_name) {
    MODE = get_elf_class(elf_name);
    if (MODE == ELFCLASS32) {
        Elf32_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_addr;
    } else if (MODE == ELFCLASS64) {
        Elf64_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_addr;
    }
}

/**
 * @brief Get the section file offset address
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section file offset address
 */
int get_section_offset(char *elf_name, char *section_name) {
    MODE = get_elf_class(elf_name);
    if (MODE == ELFCLASS32) {
        Elf32_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_offset;
    } else if (MODE == ELFCLASS64) {
        Elf64_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_offset;
    }
}

/**
 * @brief Get the section size
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section size
 */
int get_section_size(char *elf_name, char *section_name) {
    MODE = get_elf_class(elf_name);
    if (MODE == ELFCLASS32) {
        Elf32_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_size;
    } else if (MODE == ELFCLASS64) {
        Elf64_Shdr section_info;
        get_section(elf_name, section_name, &section_info);
        return section_info.sh_size;
    }
}

/**
 * @brief 向ELF文件特定偏移处，写入一段数据
 * Write a piece of data to a specific offset in the ELF file
 * @param elf_name elf file name
 * @param offset start elf file offset
 * @param content new value string value to be edited
 * @param size content size
 * @return int error code {-1:error,0:sucess}
 */
static int set_content(char *elf_name, uint64_t offset, char *content, size_t size) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *start_addr;

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

    start_addr = elf_map + offset;
    if (!start_addr) {
        goto ERR_EXIT;
    }
    if (
        validated_offset(start_addr, elf_map, elf_map + st.st_size) ||
        validated_offset(start_addr + size, elf_map, elf_map + st.st_size)
    ) {
        goto ERR_EXIT;
    }

    printf("%s->%s\n", start_addr, content);
    memset(start_addr, 0, size);
    memcpy(start_addr, content, size);

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;

ERR_EXIT:
    close(fd);
    munmap(elf_map, st.st_size);
    return -1;
}

/**
 * @brief 设置新的解释器（动态链接器）
 * Set up a new interpreter (dynamic linker)
 * @param elf_name elf file name
 * @param new_interpreter string
 * @return int error code {-1:error,0:sucess}
 */
int set_interpreter(char *elf_name, char *new_interpreter) {
    uint64_t offset = get_section_offset(elf_name, ".interp");
    size_t size = get_section_size(elf_name, ".interp");
    // 如果新的解释器的名字的长度小于原有的长度，则不需要修改ELF文件大小
    // If the length of the name of the new interpreter is less than the original length,
    // there is no need to modify the ELF file size
    if (strlen(new_interpreter) + 1 <= size) {
        return set_content(elf_name, offset, new_interpreter, strlen(new_interpreter) + 1);
    }

    else {
        // TODO:
        //offset = add_segment(elf_name, PT_LOAD, strlen(new_interpreter) + 1);
        //set_segment_offset(elf_name, offset);
    }
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
static int get_segment_range(char *elf_name, int type, uint64_t *start, uint64_t *end) {
    MODE = get_elf_class(elf_name);
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

    *start = low;
    *end = high; 

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

/**
 * @brief 增加一个段
 * add a segment
 * @param elf_name 
 * @param type segment type
 * @param start segment size
 * @return int segment offset
 */
int add_segment(char *elf_name, int type, size_t size) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    uint64_t phdr_start;
    uint64_t phdr_end;
    size_t phdr_size;
    size_t file_size;

    // 计算LOAD段的地址空间范围
    // calculate the address space range of the LOAD segment
    uint64_t vstart, vend;
    get_segment_range(elf_name, type, &vstart, &vend);

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
        
        // 一个正常的ELF文件，程序头会紧挨着ELF头
        // 将程序头移动到文件末尾
        // a normal ELF file, the program header will be next to the ELF header
        // move the program header to the end of the file
        if (phdr_end != file_size) {
            // 扩展文件大小
            file_size += phdr_size;
            file_size += sizeof(Elf32_Phdr);    // 同时需要增加一个LOAD段
            ftruncate(fd, file_size);
            // 更新内存映射
            mremap(mapped, st.st_size, file_size, 1);
            if (!mapped) {
                perror("mremap");
                goto ERR_EXIT;
            }
            ehdr = (Elf32_Ehdr *)mapped;
            // 拷贝程序头
            char *phdr_tmp = malloc(phdr_size);
            memcpy(phdr_tmp, mapped + ehdr->e_phoff, phdr_size);
            memcpy(mapped + st.st_size, phdr_tmp, phdr_size);   // 移动到文件末尾
            free(phdr_tmp);
            // 更新程序头的偏移
            phdr_start = st.st_size;
            phdr_size += sizeof(Elf32_Phdr);   // 同时需要增加一个LOAD段
            phdr_end = phdr_start + phdr_size;
            ehdr->e_phoff = phdr_start;
            ehdr->e_phnum += 1;                // 同时需要增加一个LOAD段
            // PHDR的第一个表项，指向PHDR本身，主要是为了告诉加载器，PHDR本身应该映射到进程地址空间，以便程序本身可以访问它们
            // The PHDR pointing to the PHDRs tells the loader that the PHDRs themselves should be mapped 
            // to the process address space, in order to make them accessible to the program itself.
            phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
            phdr[0].p_offset = ehdr->e_phoff;
            phdr[0].p_vaddr = align_to_4k(vend);                     // 需要设置4K对齐
            phdr[0].p_paddr = align_to_4k(vend);
            phdr[0].p_filesz = phdr_size;
            phdr[0].p_memsz = phdr_size;
            // 设置增加的段的参数
            phdr[ehdr->e_phnum - 1].p_type = PT_LOAD;
            phdr[ehdr->e_phnum - 1].p_offset = ehdr->e_phoff;
            phdr[ehdr->e_phnum - 1].p_vaddr = align_to_4k(vend);     // 需要设置4K对齐
            phdr[ehdr->e_phnum - 1].p_paddr = align_to_4k(vend);
            phdr[ehdr->e_phnum - 1].p_filesz = phdr_size;
            phdr[ehdr->e_phnum - 1].p_memsz = phdr_size;
            phdr[ehdr->e_phnum - 1].p_flags = 4;
            phdr[ehdr->e_phnum - 1].p_align = 4096;
        }

        // 如果程序头在ELF文件末尾处，直接增加一个段
        // if program header is at the end of elf
        /*
        if (phdr_end == file_size) {
            // 扩展文件大小
            file_size += size;
            file_size += sizeof(Elf32_Phdr);
            ftruncate(fd, file_size);
            // 更新内存映射
            mremap(mapped, file_size - size - sizeof(Elf32_Phdr), file_size, 1);
            if (!mapped) {
                perror("mremap");
                goto ERR_EXIT;
            }
            ehdr = (Elf32_Ehdr *)mapped;
            // 拷贝程序头
            char *phdr_tmp = malloc(phdr_size);
            memcpy(phdr_tmp, mapped + ehdr->e_phoff, phdr_size);
            memcpy(mapped + ehdr->e_phoff + size, phdr_tmp, phdr_size);
            free(phdr_tmp);
            // 修改ELF头部信息
            ehdr->e_phoff += size;
            ehdr->e_phnum += 1;
            phdr_size += sizeof(Elf32_Phdr);
            // 设置新增的程序头内容
            phdr = (Elf32_Phdr *)(mapped + ehdr->e_phoff);
            phdr[ehdr->e_phnum - 1].p_type = type;
            phdr[ehdr->e_phnum - 1].p_filesz = size;
            phdr[ehdr->e_phnum - 1].p_memsz = size;
            phdr[ehdr->e_phnum - 1].p_offset = phdr_start;  // 原始地址
            phdr[ehdr->e_phnum - 1].p_vaddr = vend;         // 加载地址
        }*/
    }

    close(fd);
    munmap(mapped, file_size);
    return phdr_start;

ERR_EXIT:
    close(fd);
    munmap(mapped, file_size);
    return -1;
}