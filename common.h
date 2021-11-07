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

/* ELF class */
extern int MODE;

/* ELF architecture */
extern int ARCH;

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
 * @return {*}
 */
int create_file(char *elf_name, char *elf_map, uint32_t map_size);