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
 * @return {*}
 */
int join_elf(uint8_t *configure, uint8_t *arch, uint32_t class, uint8_t *endian) {
    uint32_t count = 0;
    uint32_t size = 0;
    uint32_t new_size = 0;
    uint8_t *new_bin_map;
    Bin *bin;
    uint8_t *point_t;   // map address
    uint8_t *point_s;   // section address

    cJSON *root = NULL;
    root = get_json_object(configure);
    if (!root) {
        ERROR("Error before: [%s]\n", cJSON_GetErrorPtr());
        return -1;
    } else {
        count = cJSON_GetArraySize(root);
        bin = (Bin *)malloc(sizeof(Bin) * count);

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
                    cJSON_Delete(root);
                    return -1;
                }

                if (fstat(fd, &st) < 0) {
                    perror("fstat");
                    cJSON_Delete(root);
                    return -1;
                }

                bin[i].size = st.st_size;
                bin[i].bin_mem = mmap(0, bin[i].size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
                if (bin[i].bin_mem == NULL) {
                    perror("mmap");
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
        printf("--30x%x\n", bin[0].base_addr);
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
        point_s = new_bin_map + sizeof(Elf32_Ehdr) + sizeof(Elf32_Shdr) * (count + 1);

        for (int i = 0; i < count; i++) {
            printf("--40x%x\n", bin[i].base_addr);
            printf("--40x%x\n", bin[i].name);
            Elf32_Shdr shdr = {
                .sh_name = 0x0,
                .sh_type = SHT_PROGBITS,      /* Program data */
                .sh_flags = SHF_EXECINSTR,    /* Executable */ 
                .sh_addr = bin[i].base_addr,  /* Bin offset */
                .sh_offset = point_s,
                .sh_size = bin[i].size,       /* Section(bin) size */
                .sh_link = 0x0,
                .sh_info = 0x0,
                .sh_addralign = 4,
                .sh_entsize = 0x0
            };
            memcpy(point_t, &shdr, sizeof(Elf32_Shdr));
            memcpy(point_s, bin[i].bin_mem, bin[i].size);
            point_t += sizeof(Elf32_Shdr);
            point_s += bin[i].size;
        }
    }

    create_file("bin", new_bin_map, new_size);
    free(new_bin_map);

    cJSON_Delete(root);
    return 0;
}