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

#include "cJSON/cJSON.h"

#define LENGTH 64
#define PATH_LENGTH LENGTH
/* generate new file name */
#define PATH_LENGTH_NEW LENGTH + 4

#define __ALIGN_MASK(x, mask) (((x) + (mask))&~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a) - 1)
#define PTR_ALIGN(p, a) ((typeof(p))ALIGN((unsigned long)(p), (a)))

#define NONE      "\e[0m"              // Clear color 清除颜色，即之后的打印为正常输出，之前的不受影响
#define L_RED     "\e[1;31m"           // Light Red 鲜红
#define L_GREEN   "\e[1;32m"           // Light Green 鲜绿
#define YELLOW    "\e[1;33m"           // Light Yellow 鲜黄

#define WARNING(format, ...) printf (""YELLOW" [!] "format""NONE"", ##__VA_ARGS__)
#define ERROR(format, ...) printf (""L_RED" [-] "format""NONE"", ##__VA_ARGS__)
#define INFO(format, ...) printf (""L_GREEN" [+] "format""NONE"", ##__VA_ARGS__)

#define UNKOWN "Unkown"

/* ELF class */
extern int MODE;

/* ELF architecture */
extern int ARCH;

typedef struct handle32 {
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    Elf32_Shdr *shstrtab;
    uint8_t *mem;
    size_t size;
} handle_t32;

typedef struct handle64 {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    Elf64_Shdr *shstrtab;
    uint8_t *mem;
    size_t size;
} handle_t64;

void log_warning(char *str);
void log_error(char *str);
void log_info(char *str);

void get_name(char *file, char *file_name);
void get_path(char *file, char *file_path);

/**
 * @description: hex string to int
 * @param {char} *hex
 * @return {*}
 */
unsigned int hex2int(char *hex);

/**
 * @description: Convert hex to printable string (将十六进制转化为可打印的字符串)
 * @param {unsigned int} hex
 * @param {char} *ret
 * @param {unsigned int} len string length
 * @return {*}
 */
int hex2str(unsigned int hex, char *ret, unsigned int len);

/**
 * @description: String reverse from start to end (指定位置的字符串逆序)
 * @param {char} *str
 * @param {int} offset
 * @param {int} length
 * @return {*}
 */
char *str_reverse(char *str, int offset, int length);

/**
 * @description: Determine whether elf is in 32-bit mode or 64-bit mode (判断elf是32位还是64位)
 * @param {char} *elf_name
 * @return {*}
 */
int get_elf_class(char *elf_name);

/**
 * @description: Get elf architecture, such as EM_386, EM_X86_64, EM_ARM and EM_MIPS. (ELF文件架构)
 * @param {char} *elf_name
 * @return {*}
 */
int get_elf_machine(char *elf_name);

/**
 * @description: Judge whether the address is the starting address of the section (判断地址是否为section起始地址)
 * @param {char} *elf_name
 * @param {int} offset
 * @return {*}
 */
int is_sec_addr(char *elf_name, int offset);

/**
 * @description: Create new file to store changes
 * @param {char} *elf_name original file name
 * @param {char} *elf_map
 * @param {uint32_t} map_size
 * @param {uint32_t} is_new
 * @return {*}
 */
int create_file(char *elf_name, char *elf_map, uint32_t map_size, uint32_t is_new);

/**
 * @description: Create json object from json file
 * @param {char} *name original json file name
 * @return {*}
 */
cJSON *get_json_object(char *name);

/**
 * @brief Extract binary fragments from the target file
 * 
 * @param input_file original file name
 * @param offset start address
 * @param size end address(size)
 */
void extract_fragment(const char *input_file, long offset, size_t size);


/* EXTERN API */
/**
 * @brief Get the section address
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section address
 */
int get_section_addr(char *elf_name, char *section_name);

/**
 * @brief Get the section file offset address
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section file offset address
 */
int get_section_offset(char *elf_name, char *section_name);

/**
 * @brief Get the section size
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @return section 
 */
int get_section_size(char *elf_name, char *section_name);

/**
 * @brief Set the section flags
 * 
 * @param elf_name original file name
 * @param section_name section name
 * @param value permission
 */
void set_section_flags1(char *elf_name, char *section_name, int value);