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
#include "parse.h"
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
 * 比较两个字符串的前n位是否相同
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
 * @brief 将命令行传入的shellcode，转化为内存实际值
 * convert the shellcode passed in from the command line to the actual value in memory
 * @param sc_str input shellcode string
 * @param sc_mem output shellcode memory
 */
int cmdline_shellcode(char *sc_str, char *sc_mem) {
    if (strlen(sc_str) % 4 != 0) 
        return -1;
    else {
        printf("shellcode: ");
        for (size_t i = 0; i < strlen(sc_str); i += 4) {
            unsigned char value;
            sscanf(&sc_str[i], "\\x%2hhx", &value);
            *(sc_mem+i/4) = value;
            printf("%02x ", value);
        }
        printf("\n");
    }
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
 * @brief 读取文件内容到buf
 * save file content
 * @param filename file name
 * @param buffer buffer, need to free
 * @return error code {-1:false,0:success}
 */
int read_file(const char* filename, char** buffer) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        return -1; 
    }

    fseek(file, 0, SEEK_END); // 将文件指针移动到文件末尾
    long size = ftell(file); // 获取文件大小
    fseek(file, 0, SEEK_SET); // 将文件指针移动回文件开头

    *buffer = (char*)malloc(size + 1); // 分配足够的内存来存储文件内容
    if (*buffer == NULL) {
        fclose(file);
        return -2; // 内存分配失败，返回-2表示错误
    }

    fread(*buffer, 1, size, file); // 读取文件内容到缓冲区
    (*buffer)[size] = '\0'; // 在末尾添加字符串结束符

    fclose(file); 
    return size; 
}

/**
 * @brief 从文件特定偏移处，读取文件内容到buffer
 * read the file content from a specific offset to buffer
 * @param filename file name
 * @param offset file offset
 * @param size file fragment size
 * @param buffer save content to buffer
 * @return error code {-1:false,0:success}
 */
int read_file_offset(const char* filename, uint64_t offset, size_t size, char** buffer) {
    FILE *file = fopen(filename, "rb");

    if (!file) {
        fprintf(stderr, "Error opening file\n");
        return -1;
    }

    // 定位到指定的偏移处
    if (fseek(file, offset, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking in file\n");
        fclose(file);
        return -1;
    }

    // 分配足够的内存来存储读取的数据
    *buffer = (char *)malloc(size);
    if (!(*buffer)) {
        fprintf(stderr, "Error allocating memory\n");
        fclose(file);
        return -1;
    }

    // 读取数据到缓冲区
    size_t bytes_read = fread(*buffer, 1, size, file);

    if (bytes_read != size) {
        fprintf(stderr, "Error reading file\n");
        free(*buffer);
        *buffer = NULL;
    }

    fclose(file);
    return 0;
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
 * @brief 判断二进制是否开启地址随机化
 * determine whether binary has enabled address randomization
 * @param elfname 
 * @return int {1:true,0:false}
 */
int is_pie(char *elfname) {
    uint64_t vstart, vend;
    get_segment_range(elfname, PT_LOAD, &vstart, &vend);
    return vstart == 0? 1: 0;
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
 * @param output fragments content
 * @return error code {-1:error,0:sucess}
 */
int extract_fragment(const char *input_file, long offset, size_t size, char *output) {
    FILE *input_fp = fopen(input_file, "rb");
    if (input_fp == NULL) {
        perror("open input file");
        return -1;
    }

    // 设置文件指针偏移量
    fseek(input_fp, offset, SEEK_SET);

    // 读取指定大小的数据
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (buffer == NULL) {
        perror("memory allocation");
        fclose(input_fp);
        return -1;
    }

    fread(buffer, 1, size, input_fp);
    for (int i = 0; i < size; i++) {
        printf("\\x%02x", buffer[i]);
    }
    printf("\n");
    if (output)
        memcpy(output, buffer, size);

    // 关闭输入文件
    fclose(input_fp);

    // 写入数据到一个新文件
    FILE *output_fp = fopen("/tmp/elfspirt_out.bin", "wb");
    if (output_fp == NULL) {
        perror("Error creating output file");
        free(buffer);
        return -1;
    }

    fwrite(buffer, 1, size, output_fp);
    printf("write to %s\n", "/tmp/elfspirt_out.bin");

    // 关闭输出文件
    fclose(output_fp);
    free(buffer);
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
int set_content(char *elf_name, uint64_t offset, char *content, size_t size) {
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
        VERBOSE("don't need to add segment\n");
        return set_content(elf_name, offset, new_interpreter, strlen(new_interpreter) + 1);
    }

    else {
        VERBOSE("add segment\n");
        int seg_i =add_segment_content(elf_name, PT_LOAD, new_interpreter, strlen(new_interpreter) + 1);
        // 原有interpreter段表指向新的load段
        // the original interpreter segment table points to the new load segment
        VERBOSE("set phdr\n");
        set_segment_offset(elf_name, 1, get_segment_offset(elf_name, seg_i));
        set_segment_vaddr(elf_name, 1, get_segment_vaddr(elf_name, seg_i));
        set_segment_paddr(elf_name, 1, get_segment_paddr(elf_name, seg_i));
        set_segment_filesz(elf_name, 1, get_segment_filesz(elf_name, seg_i));
        set_segment_memsz(elf_name, 1, get_segment_memsz(elf_name, seg_i));
        // set shdr
        VERBOSE("set shdr\n");
        int sec_i = get_section_index(elf_name, ".interp");
        set_section_off(elf_name, sec_i, get_segment_offset(elf_name, seg_i));
        set_section_addr(elf_name, sec_i, get_segment_vaddr(elf_name, seg_i));
        set_section_size(elf_name, sec_i, get_segment_filesz(elf_name, seg_i));
    }
}

/**
 * @brief 增加一个dynamic条目
 * add a dynamic segment
 * @param elf_name elf file name
 * @param dt_tag dynamic tag
 * @param dt_value dynamic value
 * @return int error code {-1:error,0:sucess}
 */
int add_dynamic_item(char *elf_name, int dt_tag, char *dt_value) {
    // use uint64_t instead of int: avoid overflow
    uint64_t index;
    uint64_t size;

    index = has_dynamic_by_tag(elf_name, dt_tag);
    if (index != -1) {
        VERBOSE("change dynamic %d to PT_NULL\n", dt_tag);
        set_dyn_tag(elf_name, index, PT_NULL);
    }

    get_dynamic_value_by_tag(elf_name, DT_STRSZ, &size);
    VERBOSE("change dynamic PT_NULL value 0x%x\n", size);
    set_dynamic_value_by_tag(elf_name, PT_NULL, &size);
    
    get_dynamic_index_by_tag(elf_name, PT_NULL, &index);
    VERBOSE("change dynamic [%d] PT_NULL to %d\n", index, dt_tag);
    set_dyn_tag(elf_name, index, dt_tag);

    VERBOSE("add a new segment for rapth name\n");
    int result = expand_dynstr_segment(elf_name, dt_value);
    if (result) {
        return -1;
    } else {
        return 0;
    }
}

/**
 * @brief 设置rpath
 * set rpath
 * @param elf_name elf file name
 * @param rpath string
 * @return int error code {-1:error,0:sucess}
 */
int set_rpath(char *elf_name, char *rpath) {
    return add_dynamic_item(elf_name, DT_RPATH, rpath);
}

/**
 * @brief 设置runpath
 * set runpath
 * @param elf_name elf file name
 * @param rpath string
 * @return int error code {-1:error,0:sucess}
 */
int set_runpath(char *elf_name, char *runpath) {
    return add_dynamic_item(elf_name, DT_RUNPATH, runpath);
}

/**
 * @brief hook外部函数
 * hook function by .got.plt
 * @param elf_name elf file name
 * @param symbol symbol name
 * @param hookfile hook function file
 * @param hook_offset hook function offset in hook file
 * @return int error code {-1:error,0:sucess}
 */
int hook_extern(char *elf_name, char *symbol, char *hookfile, uint64_t hook_offset) {
    /* 1.extract .text from shellcode binary */
    // uint64_t offset = get_section_offset(hookfile, ".text");
    // size_t size = get_section_size(hookfile, ".text");
    uint64_t offset = 0;
    int seg_i = 0;
    int ret = -1;
    /* 2.fill new segment with .text */
    seg_i = add_segment_file(elf_name, PT_LOAD, hookfile);
    ret = set_segment_flags(elf_name, seg_i, 7);
    if (ret < 0) {
        goto ERR_EXIT;
    }
    uint64_t addr = get_segment_vaddr(elf_name, seg_i);

    /* 3.replace symbol with new segment address */
    // We are trying to analyze and edit the content of the section 
    // in a different way than before. Here is a case study
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
            ret = get_rel32_name(&h32, ".rel.plt", i, &name);
            if (ret < 0) {
                goto ERR_EXIT;
            }
            if (!strncmp(name, symbol, strlen(name))) {
                offset = get_rel32_offset(&h32, ".rel.plt", i);
                break;
            }
        }
        VERBOSE("%s offset: 0x%x, new value: 0x%x\n", symbol, offset, addr + hook_offset);
        uint32_t *p = (uint32_t *)(h32.mem + offset);
        *p = addr + hook_offset;
    }

    if (MODE == ELFCLASS64) {
        h64.sec_size = sizeof(Elf64_Rela);  // init
        for (int i = 0; i < h64.sec_size / sizeof(Elf64_Rela); i++) {
            ret = get_rela64_name(&h64, ".rela.plt", i, &name);
            if (ret < 0) {
                goto ERR_EXIT;
            }
            if (!strncmp(name, symbol, strlen(name))) {
                offset = get_rela64_offset(&h64, ".rela.plt", i);
                break;
            }
        }
        VERBOSE("%s offset: 0x%x, new value: 0x%x\n", symbol, offset, addr + hook_offset);
        uint64_t *p = (uint64_t *)(h64.mem + offset);
        *p = addr + hook_offset;
    }
    
    finit_elf(&h32, &h64);

    return 0;
ERR_EXIT:
    return -1;
}

/**
 * @brief 增加一个.dynsym table条目
 * add a dynamic symbol stable item
 * @param elf_name elf file name
 * @param name dynamic symbol name
 * @param value dynamic symbol address
 * @param code_size func size
 * @return int error code {-1:error,0:sucess}
 */
int add_dynsym_entry(char *elf_name, char *name, uint64_t value, size_t code_size) {
    uint64_t size, dynstr_size;
    uint64_t addr, offset;
    int seg_i, sec_i;
    int ret;

    // 1. expand .dynstr section
    VERBOSE("1. add a new segment for .dynstr entry\n");
    dynstr_size = get_section_size(elf_name, ".dynstr");
    seg_i = expand_dynstr_segment(elf_name, name);
    if (seg_i == -1) {
        ERROR("expand .dynstr section error!\n");
        return -1;
    }

    // 2. expand .dynsym section
    VERBOSE("2. add a new segment for .dynsym entry\n");
    size = get_section_size(elf_name, ".dynsym");
    offset = get_section_offset(elf_name, ".dynsym");
    if (MODE == ELFCLASS64) {
        Elf64_Sym sym;
        sym.st_value = value;
        sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        sym.st_other = STV_DEFAULT;
        sym.st_name = dynstr_size;
        sym.st_size = code_size;
        seg_i = expand_segment(elf_name, offset, size, &sym, sizeof(Elf64_Sym));
    }
    
    // 3. set phdr
    VERBOSE("3. set phdr for DT_SYMTAB segment\n");
    addr = get_segment_vaddr(elf_name, seg_i);
    offset = get_segment_offset(elf_name, seg_i);
    size = get_segment_memsz(elf_name, seg_i);
    set_dynamic_value_by_tag(elf_name, DT_SYMTAB, &addr);
    // set_dynamic_value_by_tag(elf_name, DT_SYMENT, &size);       // entry size == size?
    
    // 4. set shdr
    VERBOSE("4. set shdr for .dynsym section\n");
    sec_i = get_section_index(elf_name, ".dynsym");
    set_section_off(elf_name, sec_i, offset);
    set_section_addr(elf_name, sec_i, addr);
    set_section_size(elf_name, sec_i, size);
    
    // 5. compute hash table
    VERBOSE("5. compute hash table\n");
    if (MODE == ELFCLASS32)
        ret = set_hash_table32(elf_name);
    if (MODE == ELFCLASS64)
        ret = set_hash_table64(elf_name);
    if (ret == -1) {
        ERROR("compute hash table error\n");
        return -1;
    }
    return 0;
}
