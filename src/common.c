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
#include "segment.h"
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
 * @brief 获取文件大小
 * obtain file size
 * @param filename file name
 * @return uint64_t file size
 */
uint64_t get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    } else {
        // 如果获取文件大小失败，返回-1或其他错误代码
        return -1;
    }
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
 * @brief 获取elf头
 * get elf header
 * @param elf_name original file name
 * @param header output argument: elf header
 * @return error code {-1:error,0:sucess}
 */
static int get_header(char *elf_name, char *header) {
    int fd;
    struct stat st;
    uint8_t *elf_map;

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
        ehdr = (Elf32_Ehdr *)elf_map;
        memcpy(header, ehdr, sizeof(Elf32_Ehdr));
    }

    /* 64bit */
    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        ehdr = (Elf64_Ehdr *)elf_map;
        memcpy(header, ehdr, sizeof(Elf64_Ehdr));
    }

    else {
        ERROR("Invalid ELF class");
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
 * @brief 获取节头表的偏移
 * get program header table offset
 * @return uint64_t section address
 */
uint64_t get_shdr_offset(char *elf_name) {
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr ehdr;
        get_header(elf_name, &ehdr);
        return ehdr.e_shoff;
    } else if (MODE == ELFCLASS64) {
        Elf64_Ehdr ehdr;
        get_header(elf_name, &ehdr);
        return ehdr.e_shoff;
    } else {
        return -1;
    }
}

/**
 * @brief 获取程序头表的偏移
 * get program header table offset
 * @return uint64_t segment address
 */
uint64_t get_phdr_offset(char *elf_name) {
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr ehdr;
        get_header(elf_name, &ehdr);
        return ehdr.e_phoff;
    } else if (MODE == ELFCLASS64) {
        Elf64_Ehdr ehdr;
        get_header(elf_name, &ehdr);
        return ehdr.e_phoff;
    } else {
        return -1;
    }
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
 * set up a new interpreter (dynamic linker)
 * @param elf_name elf file name
 * @param new_interpreter string
 * @return int error code {-1:error,0:sucess}
 */
int set_interpreter(char *elf_name, char *new_interpreter) {
    uint64_t offset = get_section_offset(elf_name, ".interp");
    size_t size = get_section_size(elf_name, ".interp");
    // 如果新的解释器的名字的长度小于原有的长度，则不需要修改ELF文件大小
    // if the length of the name of the new interpreter is less than the original length,
    // there is no need to modify the ELF file size
    if (strlen(new_interpreter) + 1 <= size) {
        VERBOSE("the length of the input string is less than the original string\n");
        return set_content(elf_name, offset, new_interpreter, strlen(new_interpreter) + 1);
    }

    else {
        VERBOSE("the length of the input string is rather than the original string\n");
        int i = add_segment(elf_name, PT_LOAD, strlen(new_interpreter) + 1);
        offset = get_segment_offset(elf_name, i);
        set_content(elf_name, offset, new_interpreter, strlen(new_interpreter) + 1);
        // 原有interpreter段表指向新的load段
        // the original interpreter segment table points to the new load segment
        set_segment_offset(elf_name, 1, offset);
        set_segment_vaddr(elf_name, 1, get_segment_vaddr(elf_name, i));
        set_segment_paddr(elf_name, 1, get_segment_paddr(elf_name, i));
        set_segment_filesz(elf_name, 1, get_segment_filesz(elf_name, i));
        set_segment_memsz(elf_name, 1, get_segment_memsz(elf_name, i));
        // set load permission
        set_segment_flags(elf_name, i, 4);
    }
}