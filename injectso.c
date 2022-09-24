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

#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "common.h"
#include "cJSON/cJSON.h"

#define X86
#define SO_LENGTH 16

uint8_t sc_x86[] = \
    /* start */
    "\x55"                            // push   ebp                                 0
    "\x89\xe5"                        // mov    ebp, esp                            1
    "\x83\xec\x28"                    // sub    esp, 28h                            3
    "\xc7\x45\xe4\x6c\x69\x62\x70"    // mov    DWORD PTR [ebp-0x1c],0x7062696c     6
    "\xc7\x45\xe8\x61\x74\x63\x68"    // mov    DWORD PTR [ebp-0x18],0x68637461     13
    "\xc7\x45\xec\x64\x65\x6d\x6f"    // mov    DWORD PTR [ebp-0x14],0x6f6d6564     20
    "\xc7\x45\xf0\x2e\x73\x6f\x00"    // mov    DWORD PTR [ebp-0x10],0x6f732e<= 16B 27
    "\x6a\x01"                        // push   0x1                                 34
    "\x8d\x6d\xe4"                    // lea    ebp, [ebp-0x1c]                     36
    "\x55"                            // push   ebp                                 39
    "\x8b\x4b\x0c"                    // mov    ecx, DWORD PTR [ebx + 0xc]          40 
    "\x81\xe9\xe0\xf4\x13\x00"        // sub    ecx, 0x0013F4E0                     43                 
    "\x81\xc1\xf0\xea\x13\x00"        // add    ecx, 0x0013EAF0                     49                
    "\xff\xd1"                        // call   ecx --> <__libc_dlopen_mode@plt>    55
    "\x83\xc4\x08"                    // add    esp, 0x8
    "\xc9"                            // leave
    /* end */
    "\xe8"                            // call   <_start> (e8 ** = _start - eip)  0x10b0 - (0x2061 + 5)
    "\x00\x00\x00\x00";

uint8_t sc_x86_64[] = \
    /* start */
    "\x55"                                      // push   rbp                       0
    "\x48\x89\xe5"                              // mov    rbp, rsp                  1
    "\x48\x83\xec\x30"                          // sub    rsp, 30h                  4
    "\x48\xb8\x6c\x69\x62\x70\x61\x74\x63\x68"  // movabs rax,0x686374617062696c    8   
    "\x48\xbb\x64\x65\x6d\x6f\x2e\x73\x6f\x00"  // movabs rbx,0x6f732e6f6d6564      18
    "\x48\x89\x45\xe0"                          // mov    QWORD PTR [rbp-0x20],rax  28
    "\x48\x89\x5d\xe8"                          // mov    QWORD PTR [rbp-0x18],rbx  32
    "\x48\x8d\x45\xe0"                          // lea    rax,[rbp-0x20]            36
    "\xbe\x01\x00\x00\x00"                      // mov    esi,0x1                   40
    "\x48\x89\xc7"                              // mov    rdi,rax                   45
    "\x4c\x8b\x8a\x68\xae\x01\x00"              // mov    r9, [rdx + 0x1ae68]       48
    "\x49\x81\xe9\xe0\x81\x13\x00"              // sub    r9, 0x0000000001381E0     55
    "\x49\x81\xc1\x00\x78\x13\x00"              // add    r9, 0x000000000137800     62
    "\x41\xff\xd1"                              // call   r9
    "\xc9"                                      // leave
    /* end */
    "\xe8\x0b\x00\x00\x00";                     // call   <_start>

uint8_t sc_mipsel[] = \
    /* start */
    /* end */
    "\x00\x00\x00\x00"                          // jal   <_ftext>
    "\x00\x00\x00\x00";                         // nop

typedef struct Offset{
    uint32_t _ld_fini;                          // ld.so
    uint32_t _ld_catch_exception_got;           
    uint32_t _ld_catch_exception;               // libc.so
    uint32_t __libc_dlopen_mode;
}AddrOffset;

int read_offset(char *json_name, AddrOffset *addr_offset, char *arch, char *version) {
    cJSON *root = NULL;
    cJSON *item = NULL;
    root = get_json_object(json_name);
    
    if (!root) {
        ERROR("Error before: [%s]\n", cJSON_GetErrorPtr());
        return -1;
    } else {
        /* architecture */
        item = cJSON_GetObjectItem(root, arch);
        if (item) {
            /* version */
            item = cJSON_GetObjectItem(item, version);
            if (item) {
                cJSON *tmp;
                tmp = cJSON_GetObjectItem(item, "_ld_fini");
                if (tmp) {
                    addr_offset->_ld_fini = hex2int(tmp->valuestring);
                } else {
                    ERROR("No _ld_fini in json file\n");
                    goto FreeJson;
                }

                tmp = cJSON_GetObjectItem(item, "_ld_catch_exception_got");
                if (tmp) {
                    addr_offset->_ld_catch_exception_got = hex2int(tmp->valuestring);
                } else {
                    ERROR("No _ld_catch_exception_got in json file\n");
                    goto FreeJson;
                }

                tmp = cJSON_GetObjectItem(item, "_ld_catch_exception");
                if (tmp) {
                    addr_offset->_ld_catch_exception = hex2int(tmp->valuestring);
                } else {
                    ERROR("No _ld_catch_exception in json file\n");
                    goto FreeJson;
                }

                tmp = cJSON_GetObjectItem(item, "__libc_dlopen_mode");
                if (tmp) {
                    addr_offset->__libc_dlopen_mode = hex2int(tmp->valuestring);
                } else {
                    ERROR("No __libc_dlopen_mode in json file\n");
                    goto FreeJson;
                }
            } else {
                ERROR("Please check libc version in json file\n");
                goto FreeJson;
            }
        } else {
            ERROR("Please check architecture in json file\n");
            goto FreeJson;
        }
    }
    cJSON_Delete(root);
    return 0;
FreeJson:
    cJSON_Delete(root);
    return -1;    
}

/**
 * @description: Write offset according to different libc (根据不同的libc，修改汇编代码中的偏移)
 * @param {char} *json_name
 * @param {char} *arch
 * @param {char} *version
 * @return {*}
 */
int init_dlopen(char *json_name, char *arch, char *version) {
    uint32_t tmp_off;
    uint8_t tmp_off_str[4];
    AddrOffset addr_offset;

    if (read_offset(json_name, &addr_offset, arch, version)){
        exit(-1);
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        /* mov    ecx, DWORD PTR [ebx + _ld_catch_exception_got(offest->.got.plt)] */
        tmp_off = addr_offset._ld_catch_exception_got;
        hex2str(tmp_off, tmp_off_str, 1);
        memcpy(sc_x86 + 42, tmp_off_str, 1);

        /* sub    ecx, _ld_catch_exception */
        tmp_off = addr_offset._ld_catch_exception;
        hex2str(tmp_off, tmp_off_str, 4);
        memcpy(sc_x86 + 45, tmp_off_str, 4);

        /* add    ecx, __libc_dlopen_mode */
        tmp_off = addr_offset.__libc_dlopen_mode;
        hex2str(tmp_off, tmp_off_str, 4);
        memcpy(sc_x86 + 51, tmp_off_str, 4);
    }
    
    /* 64bit */
    if (MODE == ELFCLASS64) {
        /* mov r9, [rdx + _ld_catch_exception_got - _ld_fini] */
        tmp_off = addr_offset._ld_catch_exception_got - addr_offset._ld_fini;
        hex2str(tmp_off, tmp_off_str, 4);
        memcpy(sc_x86_64 + 51, tmp_off_str, 4);

        /* sub r9, _ld_catch_exception */
        tmp_off = addr_offset._ld_catch_exception;
        hex2str(tmp_off, tmp_off_str, 4);
        memcpy(sc_x86_64 + 58, tmp_off_str, 4);

        /* add r9, __libc_dlopen_mode */
        tmp_off = addr_offset.__libc_dlopen_mode;
        hex2str(tmp_off, tmp_off_str, 4);
        memcpy(sc_x86_64 + 65, tmp_off_str, 4);
    } 
    
    return 0;
}

/**
 * @description: Write file name to stack (将文件名写入栈)
 * @param {char} *path
 * @param {int} size <= 16B
 * @return {*}
 */
int name2mem(char *path, int size) {
    char revstr[PATH_LENGTH];
    /* 32bit */
    if (MODE == ELFCLASS32) {
        if (size <= SO_LENGTH) {
            for (int i = 0; i <= size / 4; i++) {
                // 9:offset 7: instruction length
                char *asm_start = sc_x86 + 9 + i * 7;
                memcpy(asm_start, path + i * 4, 4);
            }
        } else {
            ERROR("The string length is greater than %d bytes!\n", SO_LENGTH);
            exit(-1);
        } 
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        if (size <= SO_LENGTH) {
            for (int i = 0; i <= size / 8; i++) {
                char *asm_start = sc_x86_64 + 10 + i * 10;
                memcpy(asm_start, path + i * 8, 8);
            }
        } else {
            ERROR("The string length is greater than %d bytes!\n", SO_LENGTH);
            exit(-1);
        }
    }       
}

/**
 * @description: Generate the JAL instruction according to the address to jump (根据要跳转的地址，生成jal指令)
 * @param {unsigned int} addr
 * @return {*}
 */
int mips_jal_insn(unsigned int addr) {
    return ((addr & 0b1111111111111111111111111111) >> 2) + (0b11 << 26);
}

/**
 * @description: Modify the content of a section of elf to load so (修改elf某个节的内容用于加载so)
 * @param {char} *elf_name
 * @param {char} *modify_sec_name
 * @param {char} *so_name
 * @param {char} *json_name file contains libc/ld offset
 * @param {char} *version libc or ld version
 * @return {*}
 */
int inject_so(char *elf_name, char *modify_sec_name, char *so_name, char *json_name, char *version) {
    MODE = get_elf_class(elf_name);
    ARCH = get_elf_machine(elf_name);
    name2mem(so_name, strlen(so_name) - 1);
    char arch[10];
    memset(arch, 0, 10);

    switch (ARCH) {
        case EM_386:
            strcpy(arch, "x86");
            init_dlopen(json_name, arch, version);
            break;
        
        case EM_X86_64:
            strcpy(arch, "x86_64");
            init_dlopen(json_name, arch, version);
            break;
        
        default:
            ERROR("Sorry, current architecture is not supported\n");
            return -1;
            break;
    }   

    INFO("architecture: %s\n", arch); 

    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *sec_name;

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
        Elf32_Phdr *phdr;
        Elf32_Shdr shstrtab;
        Elf32_Shdr sec_text;
        uint32_t sec_addr;      
        uint32_t insn_call_addr;
        uint32_t tmp;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            sec_name = &elf_map[shstrtab.sh_offset + shdr[i].sh_name];
            if (strcmp(".text", sec_name) == 0) {
                sec_text = shdr[i];
                break;
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            sec_name = &elf_map[shstrtab.sh_offset + shdr[i].sh_name];
            sec_addr = shdr[i].sh_addr;

            // if (strcmp(".eh_frame", sec_name) == 0) {
            if (!strcmp(modify_sec_name, sec_name)) {
                INFO("%s\toffset: %p\tviraddr: %p\n", sec_name, shdr[i].sh_offset, shdr[i].sh_addr);
                tmp = ehdr->e_entry;
                // 1. modify entry
                ehdr->e_entry = shdr[i].sh_addr;
                
                // 2. modify section

                // asm: call _start
                if (tmp == sec_text.sh_addr)
                    insn_call_addr = tmp - (ehdr->e_entry + sizeof(sc_x86) - 1);
                else
                    insn_call_addr = sec_text.sh_addr - (ehdr->e_entry + sizeof(sc_x86) - 1);
                uint8_t jmp_start[4];
                hex2str(insn_call_addr, jmp_start, 4);
                memcpy(&sc_x86[sizeof(sc_x86) - 5], jmp_start, 4);
                memcpy(&elf_map[shdr[i].sh_offset], sc_x86, sizeof(sc_x86));
                INFO("%s: %s\n", sec_name, sc_x86);
                // asm: call <__libc_dlopen_mode@plt>
                INFO("entry point address: %p -> %p\n", tmp, ehdr->e_entry);
                break;
            }        
        }

        /* .eh_frame->LOAD R-E */
        phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_vaddr <= sec_addr && sec_addr < phdr[i].p_vaddr + phdr[i].p_memsz) {
                if (phdr[i].p_type == PT_LOAD) {
                    uint32_t tmp = phdr[i].p_flags;
                    phdr[i].p_flags = PF_R | PF_X;
                    INFO("LOAD offset: %p\tvaddr: %p\n", phdr[i].p_offset, phdr[i].p_vaddr);
                    INFO("LOAD flag: %p -> %p\n", tmp, phdr[i].p_flags);
                    break;
                }            
            }
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr shstrtab;
        Elf64_Shdr sec_text;
        uint64_t sec_addr;        
        uint64_t insn_call_addr;
        uint64_t tmp;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            sec_name = &elf_map[shstrtab.sh_offset + shdr[i].sh_name];
            if (strcmp(".text", sec_name) == 0) {
                sec_text = shdr[i];
                break;
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            sec_name = &elf_map[shstrtab.sh_offset + shdr[i].sh_name];
            sec_addr = shdr[i].sh_addr;

            // if (strcmp(".eh_frame", sec_name) == 0) {
            if (!strcmp(modify_sec_name, sec_name)) {
                INFO("%s\toffset: %p\tviraddr: %p\n", sec_name, shdr[i].sh_offset, shdr[i].sh_addr);
                tmp = ehdr->e_entry;
                // 1. modify entry
                ehdr->e_entry = shdr[i].sh_addr;
                
                // 2. modify section
                if (tmp == sec_text.sh_addr)
                    insn_call_addr = tmp - (ehdr->e_entry + sizeof(sc_x86_64) - 1);
                else
                    insn_call_addr = sec_text.sh_addr - (ehdr->e_entry + sizeof(sc_x86_64) - 1);
                uint8_t jmp_start[4];
                hex2str(insn_call_addr, jmp_start, 4);
                memcpy(&sc_x86_64[sizeof(sc_x86_64) - 5], jmp_start, 4);
                memcpy(&elf_map[shdr[i].sh_offset], sc_x86_64, sizeof(sc_x86_64));
                INFO("%s: %s\n", sec_name, sc_x86_64);
                INFO("entry point address: %p -> %p\n", tmp, ehdr->e_entry);
                break;
            }        
        }

        /* .eh_frame->LOAD R-E */
        phdr = (Elf64_Phdr *)&elf_map[ehdr->e_phoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_vaddr <= sec_addr && sec_addr < phdr[i].p_vaddr + phdr[i].p_memsz) {
                if (phdr[i].p_type == PT_LOAD) {
                    uint32_t tmp = phdr[i].p_flags;
                    phdr[i].p_flags = PF_R | PF_X;
                    INFO("LOAD offset: %p\tvaddr: %p\n", phdr[i].p_offset, phdr[i].p_vaddr);
                    INFO("LOAD flag: %p -> %p\n", tmp, phdr[i].p_flags);
                    break;
                }            
            }
        }
    }

#ifdef MIPSEL
    uint8_t jmp_start[4];
    hex2str(mips_jal_insn(sec_text.sh_addr), jmp_start);
    memcpy(&sc_mipsel[sizeof(sc_mipsel) - 8], jmp_start, 4);
    memcpy(&elf_map[shdr[i].sh_offset - 1], sc_mipsel, sizeof(sc_mipsel));
    printf("-------%p----%p\n\n", shdr[i].sh_offset, shdr[i].sh_addr);
#endif  

    /* new file */
    create_file(elf_name, elf_map, st.st_size);

    munmap(elf_map, st.st_size);
    close(fd);

    return 0;
}