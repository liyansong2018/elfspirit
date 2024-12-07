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

#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "addsec.h"
#include "injectso.h"
#include "delsec.h"
#include "delshtab.h"
#include "parse.h"
#include "common.h"
#include "addelfinfo.h"
#include "joinelf.h"
#include "edit.h"
#include "segment.h"

#define VERSION "1.6"
#define CONTENT_LENGTH 1024 * 1024

char section_name[LENGTH];
char string[PAGE_SIZE];
char config_name[PAGE_SIZE];
char arch[LENGTH];
char endian[LENGTH];
char ver[LENGTH];
char ver_elfspirt[LENGTH];
char elf_name[LENGTH];
char function[LENGTH];
char *g_shellcode;
uint64_t base_addr;
uint32_t size;
uint32_t off;
uint32_t class;
uint32_t value;
uint32_t row;
uint32_t column;
uint32_t length;
parser_opt_t po;
/* Additional long parameters */
static int g_long_option;
enum LONG_OPTION {
    SET_SECTION_FLAGS = 1,
    SET_SEGMENT_FLAGS,
    SET_INTERPRETER,
    ADD_SEGMENT,
    ADD_SECTION,
    INFECT_SILVIO,
    INFECT_SKEKSI,
};

/**
 * @description: obtain tool version
 */
static int get_version(char *ver, size_t len) {
    int fd;
    int ret;

    fd = open("./VERSION", O_RDONLY);
    if (fd < 0) {
        ret = strcpy(ver, VERSION);
        return ret;
    }

    ret = read(fd, ver, len);
    close(fd);
    return ret;
}

/**
 * @description: initialize arguments
 */
static void init() {
    memset(section_name, 0, LENGTH);
    memset(string, 0, LENGTH);
    memset(config_name, 0, LENGTH);
    memset(elf_name, 0, LENGTH);
    memset(function, 0, LENGTH);
    size = 0;
    off = 0;
    get_version(ver_elfspirt, LENGTH);
    po.index = 0;
    memset(po.options, 0, sizeof(po.options));
}
static const char *shortopts = "n:z:f:c:a:m:e:b:o:v:i:j:l:h::AHSPBDLR";

static const struct option longopts[] = {
    {"section-name", required_argument, NULL, 'n'},
    {"section-size", required_argument, NULL, 'z'},
    {"file-name", required_argument, NULL, 'f'},
    {"configure-name", required_argument, NULL, 'c'},
    {"architcture", required_argument, NULL, 'a'},
    {"class", required_argument, NULL, 'm'},
    {"value", required_argument, NULL, 'm'},
    {"endian", required_argument, NULL, 'e'},
    {"base", required_argument, NULL, 'b'},
    {"offset", required_argument, NULL, 'o'},
    {"lib-version", required_argument, NULL, 'v'},
    {"help", optional_argument, NULL, 'h'},
    {"index", required_argument, NULL, 'i'},
    {"row", required_argument, NULL, 'i'},
    {"column", required_argument, NULL, 'j'},
    {"length", required_argument, NULL, 'l'},
    {"set-section-flags", no_argument, &g_long_option, SET_SECTION_FLAGS},
    {"set-segment-flags", no_argument, &g_long_option, SET_SEGMENT_FLAGS},
    {"set-interpreter", no_argument, &g_long_option, SET_INTERPRETER},
    {"add-segment", no_argument, &g_long_option, ADD_SEGMENT},
    {"add-section", no_argument, &g_long_option, ADD_SECTION},
    {"infect-silvio", no_argument, &g_long_option, INFECT_SILVIO},
    {"infect-skeksi", no_argument, &g_long_option, INFECT_SKEKSI},
    {0, 0, 0, 0}
};

/**
 * @description: the online help text.
 */
static const char *help = 
    "Usage: elfspirit [function] [option]<argument>... ELF\n"
    "Currently defined functions:\n"
    "  addsec           Add a section in a ELF file\n"
    "  delsec           Delete a section of ELF file\n"
    "  injectso         Inject dynamic link library statically \n"
    "  delshtab         Delete section header table\n"
    "  parse            Parse ELF file statically like readelf\n"
    "  addelfinfo       Add ELF info to firmware for IDA\n"
    "  joinelf          Connect bin in firmware for IDA\n"
    "  extract          Extract binary fragments from the target file, like `dd` command\n"
    "  edit             Modify section information\n"
    "Currently defined options:\n"
    "  -n, --section-name=<section name>         Set section name\n"
    "  -z, --section-size=<section size>         Set section size\n"
    "  -f, --file-name=<file name>               File containing code(e.g. so, etc.)\n"
    "      --string-name=<string name>           String value\n"
    "  -c, --configure-name=<file name>          File containing configure(e.g. json, etc.)\n"
    "  -a, --architecture=<ELF architecture>     ELF architecture\n"
    "  -m, --class=<ELF machine>                 ELF class(e.g. 32bit, 64bit, etc.)\n"
    "      --value=<math value>                  Reserve value(e.g. 7=111=rwx)\n"
    "  -e, --endian=<ELF endian>                 ELF endian(e.g. little, big, etc.)\n"
    "  -b, --base=<ELF base address>             ELF base address\n"
    "  -o, --offset=<injection offset>           Offset of injection point\n"
    "  -i, --row=<object index>                  Index of the object to be read or written\n"
    "  -j, --column=<vertical axis>              The vertical axis of the object to be read or written\n"
    "  -l, --length=<string length>              Display the maximum length of the string\n"
    "  -v, --version-libc=<libc version>         Libc.so or ld.so version\n"
    "  -h, --help[={none|English|Chinese}]       Display this output\n"
    "  -A, (no argument)                         Display all ELF file infomation\n"
    "  -H, (no argument)                         Display the ELF file header\n"
    "  -S, (no argument)                         Display | Edit the section header\n"
    "  -P, (no argument)                         Display | Edit the program header\n"
    "  -B, (no argument)                         Display | Edit .symtab information\n"
    "  -D, (no argument)                         Display | Edit .dynsym information\n"
    "  -L, (no argument)                         Display | Edit .dynamic information\n"
    "  -R, (no argument)                         Display | Edit relocation section\n"
    "Detailed Usage: \n"
    "  elfspirit addsec   [-n]<section name> [-z]<section size> [-o]<offset(optional)> ELF\n"
    "  elfspirit injectso [-n]<section name> [-f]<so name> [-c]<configure file>\n"
    "                     [-v]<libc version> ELF\n"
    "  elfspirit delsec   [-n]<section name> ELF\n"
    "                     [-c]<multi section name> ELF\n"
    "  elfspirit delshtab ELF\n"
    "  elfspirit parse [-A|H|S|P|B|D|R] ELF\n"
    "  elfspirit addelfinfo [-a]<arm|x86> [-m]<32|64> [-e]<little|big> [-b]<base address>\n"
    "                     ELF\n"
    "  elfspirit joinelf [-a]<arm|x86> [-m]<32|64> [-e]<little|big> [-c]<configuration file>\n"
    "                     OUT_ELF\n"
    "  elfspirit extract  [-n]<section name> ELF\n"
    "  elfspirit extract  [-o]<file offset> [-z]<size> string\n"
    "  elfspirit edit [-H|S|P|B|D|R] [-i]<row> [-j]<column> [-m|-f]<int|string value> string\n"
    "  elfspirit --set-section-flags [-i]<row of section> [-m]<permission> string\n"
    "  elfspirit --set-segment-flags [-i]<row of segment> [-m]<permission> string\n"
    "  elfspirit --set-interpreter [-f]<new interpreter> string\n"
    "  elfspirit --add-section [-z]<size> string\n"
    "  elfspirit --add-segment [-z]<size> string\n"
    "  elfspirit --infect-silvio [-f]<shellcode> [-z]<size> string\n"
    "  elfspirit --infect-skeksi [-f]<shellcode> [-z]<size> string\n";

static const char *help_chinese = 
    "用法: elfspirit [功能] [选项]<参数>... ELF\n"
    "当前已定义的功能:\n"
    "  addsec           增加一个节\n"
    "  delsec           删除一个节\n"
    "  injectso         静态注入一个so\n"
    "  delshtab         删除节头表\n"
    "  parse            ELF文件格式分析, 类似于readelf\n"
    "  addelfinfo       为原始固件添加ELF信息, 方便IDA识别\n"
    "  joinelf          还原固件各个部分在内存中的布局\n"
    "  extract          从目标文件中提取二进制片段(like dd)\n"
    "  edit             修改节的信息\n"
    "支持的选项:\n"
    "  -n, --section-name=<section name>         设置节名\n"
    "  -z, --section-size=<section size>         设置节大小\n"
    "  -f, --file-name=<file name>               包含代码的文件名称(如某个so库)\n"
    "      --string-name=<string name>           传入字符串值\n"
    "  -c, --configure-name=<file name>          配置文件(如json)\n"
    "  -a, --architecture=<ELF architecture>     ELF文件的架构(预留选项，非必须)\n"
    "  -m, --class=<ELF machine>                 设置ELF字长(32bit, 64bit)\n"
    "      --value=<math value>                  预留的参数，可以用于传递数值(e.g. 7=111=rwx)\n"
    "  -e, --endian=<ELF endian>                 设置ELF大小端(little, big)\n"
    "  -b, --base=<ELF base address>             设置ELF入口地址\n"
    "  -o, --offset=<injection offset>           注入点的偏移位置(预留选项，非必须)\n"
    "  -i, --row=<object index>                  待读出或者写入的对象的下标\n"
    "  -j, --column=<vertical axis>              待读出或者写入的对象的纵坐标\n"
    "  -l, --length=<string length>              解析ELF文件时，显示字符串的最大长度\n"
    "  -v, --version-libc=<libc version>         libc或者ld的版本\n"
    "  -h, --help[={none|English|Chinese}]       帮助\n"
    "  -A, 不需要参数                    显示ELF解析器解析的所有信息\n"
    "  -H, 不需要参数                    显示ELF头\n"
    "  -S, 不需要参数                    显示|编辑ELF: 节头\n"
    "  -P, 不需要参数                    显示|编辑ELF: 程序头\n"
    "  -B, 不需要参数                    显示|编辑ELF: 静态符号表\n"
    "  -D, 不需要参数                    显示|编辑ELF: 动态符号表\n"
    "  -L, 不需要参数                    显示|编辑ELF: 动态链接\n"
    "  -R, 不需要参数                    显示|编辑ELF: 重定位表\n"
    "细节: \n"
    "  elfspirit addsec   [-n]<节的名字> [-z]<节的大小> [-o]<节的偏移(可选项)> ELF\n"
    "  elfspirit injectso [-n]<节的名字> [-f]<so的名字> [-c]<配置文件>\n"
    "                     [-v]<libc的版本> ELF\n"
    "  elfspirit delsec   [-n]<节的名字> ELF\n"
    "                     [-c]<多个节的名字> ELF\n"
    "  elfspirit delshtab ELF\n"
    "  elfspirit parse [-A|H|S|P|B|D|R] ELF\n"
    "  elfspirit addelfinfo [-a]<arm|x86> [-m]<32|64> [-e]<little|big> [-b]<基地址>\n"
                            "ELF\n"
    "  elfspirit joinelf [-a]<arm|x86> [-m]<32|64> [-e]<little|big> [-c]<配置文件>\n"
    "                     OUT_ELF\n"
    "  elfspirit edit [-H|S|P|B|D|R] [-i]<第几行> [-j]<第几列> [-m|-f]<int|str修改值> ELF\n"
    "  elfspirit --set-section-flags [-i]<第几个节> [-m]<权限值> ELF\n"
    "  elfspirit --set-segment-flags [-i]<第几个段> [-m]<权限值> ELF\n"
    "  elfspirit --set-interpreter [-f]<新的链接器> ELF\n"
    "  elfspirit --add-section [-z]<size> ELF\n"
    "  elfspirit --add-segment [-z]<size> ELF\n"
    "  elfspirit --infect-silvio [-f]<shellcode> [-z]<size> string\n"
    "  elfspirit --infect-skeksi [-f]<shellcode> [-z]<size> string\n";

static void readcmdline(int argc, char *argv[]) {
    int opt;
    if (argc == 1) {
        printf("Current version: %s\n", ver_elfspirt);
        fputs(help, stdout);
    }
    while((opt = getopt_long(argc, argv, shortopts, longopts, NULL)) != EOF) {
        /* The row of options cannot be greater than the array capacity */
        if (po.index >= sizeof(po.options)) {
            break;
        }
        switch (opt) {
            // set section name
            case 'n':
                memcpy(section_name, optarg, LENGTH);
                break;
            
            // set section size
            case 'z':
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    size = hex2int(optarg);
                }
                else{
                    size = atoi(optarg);
                }                
                break;
            
            // set file name
            case 'f':
                memcpy(string, optarg, strlen(optarg));
                break;

            // configure
            case 'c':
                memcpy(config_name, optarg, LENGTH);
                break;

            /***** add elf info to firmware for IDA - STRT*****/
            // set architecture
            case 'a':
                memcpy(arch, optarg, LENGTH);
                break;

            // set class
            case 'm':
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    class = hex2int(optarg);
                }
                else{
                    class = atoi(optarg);
                }
                value = class;
                break;
            
            // set endian
            case 'e':
                memcpy(endian, optarg, LENGTH);
                break;

            // set base address
            case 'b':
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    base_addr = hex2int(optarg);
                }
                else{
                    base_addr = atoi(optarg);
                }                
                break;
            /***** add elf info to firmware for IDA - END *****/

            // set offset
            case 'o':
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    off = hex2int(optarg);
                }
                else{
                    off = atoi(optarg);
                }                
                break;

            // set libc version
            case 'v':
                memcpy(ver, optarg, LENGTH);
                break;
            
            case 'h':
                if (optarg != NULL && !strcmp(optarg, "Chinese")){       
                    fputs(help_chinese, stdout);
                    printf("当前版本: %s\n", ver_elfspirt);
                }
                else {
                    fputs(help, stdout);
                    printf("Current version: %s\n", ver_elfspirt);                
                }                    
                           
                break;

            case 'i':
                if (strlen(optarg) > 1 && optarg[0] == '0' && optarg[1] == 'x') {
                    row = hex2int(optarg);
                }
                else{
                    row = atoi(optarg);
                }                
                break;

            case 'j':
                if (strlen(optarg) > 1 && optarg[0] == '0' && optarg[1] == 'x') {
                    column = hex2int(optarg);
                }
                else{
                    column = atoi(optarg);
                }                
                break;

            case 'l':
                if (strlen(optarg) > 1 && optarg[0] == '0' && optarg[1] == 'x') {
                    length = hex2int(optarg);
                }
                else{
                    length = atoi(optarg);
                }                
                break;

            /* ELF parser's options */
            case 'A':
                po.options[po.index++] = ALL;
                break;
            case 'H':
                po.options[po.index++] = HEADERS;
                break;
            
            case 'S':
                po.options[po.index++] = SECTIONS;
                break;

            case 'P':
                po.options[po.index++] = SEGMENTS;
                break;
            
            case 'B':
                po.options[po.index++] = SYMTAB;
                break;

            case 'D':
                po.options[po.index++] = DYNSYM;
                break;

            case 'L':
                po.options[po.index++] = LINK;
                break;

            case 'R':
                po.options[po.index++] = RELA;
                break;
            
            default:
                break;
        }
    }

    /* handle additional long parameters */
    if (optind == argc - 1) {
        memcpy(elf_name, argv[optind], LENGTH);
        MODE = get_elf_class(elf_name);
        if (g_long_option) {
            switch (g_long_option)
            {
                case SET_SECTION_FLAGS:
                    /* modify section information */
                    set_section_flags(elf_name, row, value);
                    break;

                case SET_SEGMENT_FLAGS:
                    /* modify segment information */
                    set_segment_flags(elf_name, row, value);
                    break;

                case SET_INTERPRETER:
                    /* set new interpreter */
                    set_interpreter(elf_name, string);
                    break;

                case ADD_SEGMENT:
                    /* add a segment */
                    add_segment(elf_name, PT_LOAD, size);
                    break;

                case ADD_SECTION:
                    /* add a section */
                    add_section(elf_name, size);
                    break;

                case INFECT_SILVIO:
                    /* infect using silvio */
                    g_shellcode = malloc(size + 1);
                    cmdline_shellcode(string, g_shellcode);
                    g_shellcode[size] = '\0';
                    infect_silvio(elf_name, g_shellcode, size + 1);
                    free(g_shellcode);
                    break;

                case INFECT_SKEKSI:
                    /* infect using skeksi plus */
                    g_shellcode = malloc(size + 1);
                    cmdline_shellcode(string, g_shellcode);
                    g_shellcode[size] = '\0';
                    infect_skeksi_pie(elf_name, g_shellcode, size + 1);
                    free(g_shellcode);
                    break;
                
                default:
                    break;
            }
        }
        exit(-1);
    }

    else if (optind != argc - 2) {
        exit(-1);
    }
    /* handle additional function parameters */
    else {
        memcpy(function, argv[optind], LENGTH);
        memcpy(elf_name, argv[++optind], LENGTH);
    }

    /* add a section */
    if (!strcmp(function, "addsec")) {
        add_section_bak(elf_name, off, section_name, size);
    }

    /* inject so */
    if (!strcmp(function, "injectso")) {
        char *so_name = string;
        inject_so(elf_name, section_name, so_name, config_name, ver);
    }

    /* delete a section */
    if (!strcmp(function, "delsec")) {
        delete_section(elf_name, section_name, config_name);
    }

    /* delete a section */
    if (!strcmp(function, "delshtab")) {
        delete_shtab(elf_name);
    }

    /* ELF parser */
    if (!strcmp(function, "parse")) {
        parse(elf_name, &po, length);
    }

    /* add elf info to firmware for IDA */
    if (!strcmp(function, "addelfinfo")) {
        add_elf_info(elf_name, arch, class, endian, base_addr);
    }

    /* connect each bin in firmware for IDA */
    if (!strcmp(function, "joinelf")) {
        join_elf(config_name, arch, class, endian, elf_name);
    }

    /* extract binary fragments */
    if (!strcmp(function, "extract")) {
        if (strlen(section_name) != 0) {
            off = get_section_offset(elf_name, section_name);
            size = get_section_size(elf_name, section_name);
            extract_fragment(elf_name, off, size);
        } else if (size != 0) {
            extract_fragment(elf_name, off, size);
        }
    }

    /* edit elf */
    if (!strcmp(function, "edit")) {
        edit(elf_name, &po, row, column, value, section_name, string);
    }

    DEBUG("function: %s\n", function);
    DEBUG("elf: %s\n", elf_name);
    DEBUG("name:%s, size: %u\n", section_name, size);
}

int main(int argc, char *argv[]) {
    init();
    readcmdline(argc, argv);
    return 0;
}
