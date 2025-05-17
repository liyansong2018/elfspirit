/*
 MIT License
 
 Copyright (c) 2021-2022 SecNotes
 
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

#include <stdio.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include "cJSON/cJSON.h"

#include "common.h"

typedef struct Bininfo {
    uint8_t *name;      // bin file path and name
    uint64_t base_addr; // bin load address
    uint64_t size;      // bin size
    uint64_t bin_mem;   // bin map
}Bin;

static int conv_arch(uint8_t *arch) {
    if (!(strcmp(arch, "arm") & strcmp(arch, "ARM"))) {
        return EM_ARM;
    } 
    
    else if (!(strcmp(arch, "x86") & strcmp(arch, "X86"))) {
        return EM_386;
    } 
    
    else if (!(strcmp(arch, "mips") & strcmp(arch, "MIPS"))) {
        return EM_MIPS;
    } 
    
    else
        return NULL;
}

/**
 * @description: connect each bin in firmware for IDA
 * @param {uint8_t} *configure
 * @param {uint8_t} *arch
 * @param {uint32_t} class
 * @param {uint8_t} *endian
 * @param {uint8_t} *out
 * @return {*}
 */
int join_elf(uint8_t *configure, uint8_t *arch, uint32_t class, uint8_t *endian, uint8_t *out) {
    uint32_t count = 0;
    uint32_t size = 0;
    uint32_t new_size = 0;
    uint8_t *new_bin_map;
    Bin *bin;
    uint8_t *point_t;   // map address
    uint32_t offset_t;   // section address

    cJSON *root = NULL;
    root = get_json_object(configure);
    if (!root) {
        ERROR("Error before: [%s]\n", cJSON_GetErrorPtr());
        return -1;
    } else {
        count = cJSON_GetArraySize(root);
        bin = (Bin *)malloc(sizeof(Bin) * count);
        if (bin == NULL) {
            perror("malloc");
            return -1;
        }

        for (int i = 0; i < count; i++) {
            cJSON *item = cJSON_GetArrayItem(root, i);
            if (!cJSON_IsNull(item) & item->type == cJSON_String) {
                bin[i].base_addr = hex2int(item->string);
                bin[i].name = item->valuestring;
                int fd = open(bin[i].name, O_RDONLY);
                struct stat st;
                if (fd < 0) {
                    ERROR("%s\n", bin[i].name);
                    perror("open in join_elf");
                    free(bin);
                    cJSON_Delete(root);
                    return -1;
                }

                if (fstat(fd, &st) < 0) {
                    perror("fstat");
                    free(bin);
                    cJSON_Delete(root);
                    return -1;
                }

                bin[i].size = st.st_size;
                bin[i].bin_mem = mmap(0, bin[i].size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
                if (bin[i].bin_mem == NULL) {
                    perror("mmap");
                    free(bin);
                    cJSON_Delete(root);
                    return -1;
                }

                size += bin[i].size;
                close(fd);
            }
        }
    }

    if (class == 32) {
        /*****| ELF Header | ELF Section header1 | ELF Section header2 |*****/
        new_size = sizeof(Elf32_Ehdr) + sizeof(Elf32_Shdr) * (count + 1) + size;
        new_bin_map = malloc(new_size);
        memset(new_bin_map, 0, new_size);
        Elf32_Ehdr ehdr = {
            .e_ident = 0x0,
            .e_type = ET_EXEC,
            .e_machine = conv_arch(arch),
            .e_version = EV_CURRENT,
            .e_entry = bin[0].base_addr,
            .e_phoff = 0,
            .e_shoff = sizeof(Elf32_Ehdr),
            .e_flags = 0,
            .e_ehsize = sizeof(Elf32_Ehdr),
            .e_phentsize = sizeof(Elf32_Phdr),
            .e_phnum = 0,
            .e_shentsize = sizeof(Elf32_Shdr),
            .e_shnum = 2,
            .e_shstrndx = 0,
        };
        if (ehdr.e_machine == EM_ARM) {
            ehdr.e_flags = 0x05000200;  /* arm32 */
        }
        ehdr.e_ident[0] = '\x7f';
        ehdr.e_ident[1] = 'E';
        ehdr.e_ident[2] = 'L';
        ehdr.e_ident[3] = 'F';
        ehdr.e_ident[4] = ELFCLASS32;   /* ELF class */
        if (!strcmp(endian, "little"))
            ehdr.e_ident[5] = '\x01';      
        else if(!strcmp(endian, "big"))
            ehdr.e_ident[5] = '\x02';            
        ehdr.e_ident[6] = '\x01';       /* EI_VERSION */

        /*****| ELF Header | ELF Section header1 | ELF Section header2 |*****/
        point_t = new_bin_map;
        memcpy(point_t, &ehdr, sizeof(Elf32_Ehdr));
        point_t += sizeof(Elf32_Ehdr);
        /***** null section header *****/
        point_t += sizeof(Elf32_Shdr);
        offset_t = sizeof(Elf32_Ehdr) + sizeof(Elf32_Shdr) * (count + 1);

        for (int i = 0; i < count; i++) {
            Elf32_Shdr shdr = {
                .sh_name = 0x0,
                .sh_type = SHT_PROGBITS,      /* Program data */
                .sh_flags = SHF_EXECINSTR,    /* Executable */ 
                .sh_addr = bin[i].base_addr,  /* Bin offset */
                .sh_offset = offset_t,
                .sh_size = bin[i].size,       /* Section(bin) size */
                .sh_link = 0x0,
                .sh_info = 0x0,
                .sh_addralign = 4,
                .sh_entsize = 0x0
            };
            memcpy(point_t, &shdr, sizeof(Elf32_Shdr));
            memcpy(offset_t + new_bin_map, bin[i].bin_mem, bin[i].size);
            point_t += sizeof(Elf32_Shdr);
            offset_t += bin[i].size;
        }
    }

    create_file(out, new_bin_map, new_size, 0);
    free(new_bin_map);
    free(bin);
    cJSON_Delete(root);
    return 0;
}