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

#define CONTENT_LENGTH 1024 * 1024

char section_name[LENGTH];
char file_name[LENGTH];
char config_name[LENGTH];
char arch[LENGTH];
char ver[LENGTH];
char ver_elfspirt[LENGTH];
char elf_name[LENGTH];
char function[LENGTH];
uint32_t size;
uint32_t off;
parser_opt_t po;

/**
 * @description: obtain tool version
 */
static int get_version(char *ver, size_t len) {
    int fd;
    int ret;

    fd = open("./VERSION", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
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
    memset(file_name, 0, LENGTH);
    memset(elf_name, 0, LENGTH);
    memset(function, 0, LENGTH);
    size = 0;
    off = 0;
    get_version(ver_elfspirt, LENGTH);
    po.index = 0;
    memset(po.options, 0, sizeof(po.options));
}
static const char *shortopts = "n:z:f:c:a:o:v:h::AHSPL";

static const struct option longopts[] = {
    {"section-name", required_argument, NULL, 'n'},
    {"section-size", required_argument, NULL, 'z'},
    {"file-name", required_argument, NULL, 'f'},
    {"configure-name", required_argument, NULL, 'c'},
    {"architcture", required_argument, NULL, 'a'},
    {"offset", required_argument, NULL, 'o'},
    {"lib-version", required_argument, NULL, 'v'},
    {"help", optional_argument, NULL, 'h'},
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
    "  elfspirit        Parse ELF file statically like readelf\n"
    "Currently defined options:\n"
    "  -n, --section-name=<section name>         Set section name\n"
    "  -z, --section-size=<section size>         Set section size\n"
    "  -f, --file-name=<file name>               File containing code(e.g. so, etc.)\n"
    "  -c, --configure-name=<file name>          File containing configure(e.g. json, etc.)\n"
    "  -a, --architecture=<ELF architecture>     ELF architecture\n"
    "  -o, --offset=<injection offset>           Offset of injection point\n"
    "  -v, --version-libc=<libc version>         Libc.so or ld.so version\n"
    "  -h, --help[={none|English|Chinese}]       Display this output\n"
    "  -A, (no argument)                         Display all ELF file infomation\n"
    "  -H, (no argument)                         Display the ELF file header\n"
    "  -S, (no argument)                         Display the sections' header\n"
    "  -P, (no argument)                         Display the program headers\n"
    "  -L, (no argument)                         Display the link information\n"
    "Detailed Usage: \n"
    "  elfspirit addsec   [-n]<section name> [-z]<section size> [-o]<offset(optional)> ELF\n"
    "  elfspirit injectso [-n]<section name> [-f]<so name> [-c]<configure file>\n"
    "                     [-v]<libc version> ELF\n"
    "  elfspirit delsec   [-n]<section name> ELF\n"
    "  elfspirit delshtab ELF\n"
    "  elfspirit parse -A ELF\n";

static const char *help_chinese = 
    "用法: elfspirit [功能] [选项]<参数>... ELF\n"
    "当前已定义的功能:\n"
    "  addsec           增加一个节\n"
    "  delsec           删除一个节\n"
    "  injectso         静态注入一个so\n"
    "  delshtab         删除节头表\n"
    "  elfspirit        ELF文件格式分析, 类似于readelf\n"
    "支持的选项:\n"
    "  -n, --section-name=<section name>         设置节名\n"
    "  -z, --section-size=<section size>         设置节大小\n"
    "  -f, --file-name=<file name>               包含代码的文件名称(如某个so库)\n"
    "  -c, --configure-name=<file name>          配置文件(如json)\n"
    "  -a, --architecture=<ELF architecture>     ELF文件的架构(预留选项，非必须)\n"
    "  -o, --offset=<injection offset>           注入点的偏移位置(预留选项，非必须)\n"
    "  -v, --version-libc=<libc version>         libc或者ld的版本\n"
    "  -h, --help[={none|English|Chinese}]       帮助\n"
    "  -A, 不需要参数                    显示ELF解析器解析的所有信息\n"
    "  -H, 不需要参数                    显示ELF头\n"
    "  -S, 不需要参数                    显示ELF节头\n"
    "  -P, 不需要参数                    显示ELF程序头\n"
    "  -L, 不需要参数                    显示ELF链接\n"
    "细节: \n"
    "  elfspirit addsec   [-n]<section name> [-z]<section size> [-o]<offset(optional)> ELF\n"
    "  elfspirit injectso [-n]<section name> [-f]<so name> [-c]<configure file>\n"
    "                     [-v]<libc version> ELF\n"
    "  elfspirit delsec   [-n]<section name> ELF\n"
    "  elfspirit delshtab ELF\n"
    "  elfspirit parse -A ELF\n";

static void readcmdline(int argc, char *argv[]) {
    int opt;
    if (argc == 1) {
        fputs(help, stdout);
        printf("Current version: %s\n", ver_elfspirt);
    }
    while((opt = getopt_long(argc, argv, shortopts, longopts, NULL)) != EOF) {
        /* The number of options cannot be greater than the array capacity */
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
                memcpy(file_name, optarg, LENGTH);
                break;

            // configure
            case 'c':
                memcpy(config_name, optarg, LENGTH);
                break;

            // set architecture
            case 'a':
                memcpy(arch, optarg, LENGTH);
                break;

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
                printf("%s\n", optarg);
                if (optarg != NULL && !strcmp(optarg, "Chinese")){       
                    fputs(help_chinese, stdout);
                    printf("当前版本: %s\n", ver_elfspirt);
                }
                else {
                    fputs(help, stdout);
                    printf("Current version: %s\n", ver_elfspirt);                
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

            case 'L':
                po.options[po.index++] = LINK;
                break;
            
            default:
                break;
        }
    }

    if (optind != argc - 2) {
        exit(-1);
    }
    else {
        memcpy(function, argv[optind], LENGTH);
        memcpy(elf_name, argv[++optind], LENGTH);
    }

    /* add a section */
    if (!strcmp(function, "addsec")) {
        add_section(elf_name, off, section_name, size);
    }

    /* inject so */
    if (!strcmp(function, "injectso")) {
        char *so_name = file_name;
        inject_so(elf_name, section_name, so_name, config_name, ver);
    }

    /* delete a section */
    if (!strcmp(function, "delsec")) {
        delete_section(elf_name, section_name);
    }

    /* delete a section */
    if (!strcmp(function, "delshtab")) {
        delete_shtab(elf_name);
    }

    /* ELF parser */
    if (!strcmp(function, "parse")) {
        parse(elf_name, &po);
    }

#ifdef DEBUG
    printf("%s\n", function);
    printf("%s\n", elf_name);
    printf("name:%s, size: %u\n", section_name, size);
#endif
}

int main(int argc, char *argv[]) {
    init();
    readcmdline(argc, argv);
    return 0;
}
