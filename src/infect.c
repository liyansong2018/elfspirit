/*
 MIT License
 
 Copyright (c) 2024 Yansong Li
 
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

/**
 * @brief 在文件offset偏移处插入一段数据
 * insert a piece of data at the offset of the file
 * @param elfname elf file name
 * @param offset elf file offset
 * @param data data
 * @param data_size data size
 * @return int result code {-1:error,0:false,1:true}
 */
int insert_data(const char *filename, off_t offset, const void *data, size_t data_size) {
    FILE *file = fopen(filename, "r+b");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    // 获取文件末尾位置
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);

    // 将文件指针移动到插入位置
    fseek(file, offset, SEEK_SET);

    // 读取插入位置后的数据
    char *temp_buffer = (char *)malloc(file_size - offset);
    fread(temp_buffer, file_size - offset, 1, file);

    // 将数据写入插入位置
    fseek(file, offset, SEEK_SET);
    fwrite(data, data_size, 1, file);

    // 写入剩余数据
    fwrite(temp_buffer, file_size - offset, 1, file);

    // 释放内存并关闭文件
    free(temp_buffer);
    fclose(file);
    return 0;
}

/*
                                                             
      memory layout                  file layout             
                                                             
  ─── ┌──────────────┐ 0x0000        ┌──────────────┐ 0x0000 
  ▲   │   ehdr/phdr  │          const│   ehdr/phdr  │        
  │   ├──────────────┤ 0x1000        ├──────────────┤ 0x1000 
  │   │     TEXT     │               │     TEXT     │        
  │   ├──────────────┤               ├──────────────┤        
 const│xxxxxxxxxxxxxx│               │xxxxxxxxxxxxxx│        
      ├──────────────┤               ├───────┬──────┤        
  │   │              │               │       │      │        
  │   │              │               │       │      │        
  ▼   │              │               │       ▼      │        
  ─── │              │               │   PAGE_SIZE  │        
      │              │               │              │        
      ├──────────────┤               ├──────────────┤        
      │     shdr     │               │     shdr     │        
      └──────────────┘               └──────────────┘        
                                                             
 */

/**
 * @brief 使用silvio感染算法，填充text段
 * use the Silvio infection algorithm to fill in text segments
 * @param elfname elf file name
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_silvio(char *elfname, char *parasite, size_t size) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    int text_index;
    uint64_t parasite_addr;
    uint64_t parasite_offset;

    fd = open(elfname, O_RDWR);
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

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;
        Elf32_Shdr *shdr;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
        shdr = (Elf32_Shdr *)&mapped[ehdr->e_shoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // 1. text段扩容size
                if (phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    parasite_addr = phdr[i].p_vaddr + phdr[i].p_memsz;
                    parasite_offset = phdr[i].p_offset + phdr[i].p_filesz;
                    phdr[i].p_memsz += size;
                    phdr[i].p_filesz += size;
                    VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // 2. 其他load段向后偏移
                if (phdr[i].p_offset > phdr[text_index].p_offset) {
                    //phdr[i].p_vaddr += PAGE_SIZE;
                    //phdr[i].p_paddr += PAGE_SIZE;
                    phdr[i].p_offset += PAGE_SIZE;
                }
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            // 3. 寄生代码之后的节，偏移PAGE_SIZE
            if (shdr[i].sh_offset > parasite_offset) {
                //shdr[i].sh_addr += PAGE_SIZE;
                shdr[i].sh_offset += PAGE_SIZE;
            }
            // 4. text节，偏移size
            else if (shdr[i].sh_addr + shdr[i].sh_size == parasite_addr) {
                shdr[i].sh_size += size;
            }
        }
        // 5. elf节头偏移PAGE_SIZE
        ehdr->e_shoff += PAGE_SIZE;
    }

    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];
        shdr = (Elf64_Shdr *)&mapped[ehdr->e_shoff];
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // 1. text段扩容size
                if (phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    parasite_addr = phdr[i].p_vaddr + phdr[i].p_memsz;
                    parasite_offset = phdr[i].p_offset + phdr[i].p_filesz;
                    phdr[i].p_memsz += size;
                    phdr[i].p_filesz += size;
                    VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                // 2. 其他load段向后偏移
                if (phdr[i].p_offset > phdr[text_index].p_offset) {
                    phdr[i].p_offset += PAGE_SIZE;
                }
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            // 3. 寄生代码之后的节，偏移PAGE_SIZE
            if (shdr[i].sh_offset > parasite_offset) {
                shdr[i].sh_offset += PAGE_SIZE;
            }
            // 4. text节，偏移size
            else if (shdr[i].sh_addr + shdr[i].sh_size == parasite_addr) {
                shdr[i].sh_size += size;
            }
        }
        // 5. elf节头偏移PAGE_SIZE
        ehdr->e_shoff += PAGE_SIZE;
    }

    close(fd);
    munmap(mapped, st.st_size);

    // 6. 插入寄生代码
    char *parasite_expand = malloc(PAGE_SIZE);
    memset(parasite_expand, 0, PAGE_SIZE);
    memcpy(parasite_expand, parasite, PAGE_SIZE - size > 0? size: PAGE_SIZE);
    int ret = insert_data(elfname, parasite_offset, parasite_expand, PAGE_SIZE);
    if (ret == 0) {
        VERBOSE("insert successfully\n");
    } else {
        VERBOSE("insert failed\n");
    }
    free(parasite_expand);

    return parasite_addr;
}

/*
The address of the load segment in memory cannot be easily changed
.rela.dyn->offset->.dynamic
                                                            
      memory layout                  file layout            
                                                            
      ┌──────────────┐ 0x0000        ┌──────────────┐ 0x0000
      │xxxxxxxxxxxxxx│          const│   ehdr/phdr  │       
  ─── ├──────────────┤ 0x1000        ├──────────────┤ 0x1000
  ▲   │     TEXT     │               │xxxxxxxxxxxxxx│       
  │   ├──────────────┤               ├──────────────┤       
  │   │              │               │     TEXT     │       
 const│              │               ├──────────────┤       
  │   │              │               │              │       
  │   │              │               │              │       
  ▼   │              │               │              │       
  ─── ├──────────────┤               │              │       
      │  ehrdr/phdr  │               │              │       
      ├──────────────┤               ├──────────────┤       
      │     shdr     │               │     shdr     │       
      └──────────────┘               └──────────────┘       
                                                                     
*/                                                      

/**
 * @brief 使用skeksi增强版感染算法，填充text段. 此算法适用于开启pie的二进制
 * use the Skeksi plus infection algorithm to fill in text segments
 * this algorithm is suitable for opening binary pie
 * @param elfname elf file name
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_skeksi_pie(char *elfname, char *parasite, size_t size) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    int text_index;
    uint64_t parasite_addr;
    size_t distance;
    uint64_t min_paddr = 0x0;
    uint64_t orgin_text_vaddr = 0x0;
    uint64_t orgin_text_offset = 0x0;
    size_t orgin_text_size = 0x0;

    uint64_t vstart, vend;
    get_segment_range(elfname, PT_LOAD, &vstart, &vend);

    fd = open(elfname, O_RDWR);
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

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;
        Elf32_Shdr *shdr;
        Elf32_Dyn *dyn;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
        shdr = (Elf32_Shdr *)&mapped[ehdr->e_shoff];

        // memory layout
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                if (phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    for (int j = 0; j < i; j++) {
                        if (phdr[j].p_vaddr < min_paddr)
                            min_paddr = phdr[j].p_vaddr;
                    }
                    orgin_text_vaddr = phdr[i].p_vaddr;
                    orgin_text_size = phdr[i].p_memsz;
                    orgin_text_offset = phdr[i].p_offset;
                    phdr[i].p_memsz += PAGE_SIZE;
                    phdr[i].p_vaddr -= PAGE_SIZE;
                    phdr[i].p_paddr -= PAGE_SIZE;
                    parasite_addr = phdr[i].p_vaddr;
                    VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (i == text_index)
                continue;
            if (phdr[i].p_vaddr < orgin_text_vaddr) {
                phdr[i].p_vaddr += align_to_4k(vend);
                phdr[i].p_paddr += align_to_4k(vend);
                continue;
            }

            // if (phdr[i].p_vaddr > orgin_text_vaddr) {
            //     phdr[i].p_vaddr += PAGE_SIZE;
            // }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_addr == orgin_text_vaddr) {
                shdr[i].sh_addr -= PAGE_SIZE;
                shdr[i].sh_size += PAGE_SIZE;
            }
            else if (shdr[i].sh_addr < orgin_text_vaddr) {
                shdr[i].sh_addr += align_to_4k(vend);
            }
            // else if (shdr[i].sh_addr >= orgin_text_vaddr + orgin_text_size) {
            //     shdr[i].sh_addr += PAGE_SIZE;
            // }
        }

        // start----------------------- edit .dynamic
        // 32: REL
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                dyn = (Elf32_Dyn *)(mapped + phdr[i].p_offset);
                for (int j = 0; j < phdr[i].p_filesz / sizeof(Elf32_Dyn); j++) {
                    if (dyn[j].d_tag == DT_STRTAB |
                        dyn[j].d_tag == DT_SYMTAB |
                        dyn[j].d_tag == DT_REL | 
                        dyn[j].d_tag == DT_JMPREL | 
                        dyn[j].d_tag == DT_VERNEED | 
                        dyn[j].d_tag == DT_VERSYM) {
                            dyn[j].d_un.d_val += align_to_4k(vend);
                    } 
                }
            }
        }
        // end------------------------- edit .dynamic

        // file layout
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (i == text_index) {
                phdr[i].p_filesz += PAGE_SIZE;
                continue;
            }
            if (phdr[i].p_offset > orgin_text_offset) {
                phdr[i].p_offset += PAGE_SIZE;
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_offset >= orgin_text_offset + orgin_text_size) {
                shdr[i].sh_offset += PAGE_SIZE;
            }
        }

        // elf节头表偏移PAGE_SIZE
        ehdr->e_shoff += PAGE_SIZE;
    }

    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        Elf64_Dyn *dyn;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];
        shdr = (Elf64_Shdr *)&mapped[ehdr->e_shoff];

        // memory layout
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) {
                if (phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    for (int j = 0; j < i; j++) {
                        if (phdr[j].p_vaddr < min_paddr)
                            min_paddr = phdr[j].p_vaddr;
                    }
                    orgin_text_vaddr = phdr[i].p_vaddr;
                    orgin_text_size = phdr[i].p_memsz;
                    orgin_text_offset = phdr[i].p_offset;
                    phdr[i].p_memsz += PAGE_SIZE;
                    phdr[i].p_vaddr -= PAGE_SIZE;
                    phdr[i].p_paddr -= PAGE_SIZE;
                    parasite_addr = phdr[i].p_vaddr;
                    VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (i == text_index)
                continue;
            if (phdr[i].p_vaddr < orgin_text_vaddr) {
                phdr[i].p_vaddr += align_to_4k(vend);
                phdr[i].p_paddr += align_to_4k(vend);
                continue;
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_addr == orgin_text_vaddr) {
                shdr[i].sh_addr -= PAGE_SIZE;
                shdr[i].sh_size += PAGE_SIZE;
            }
            else if (shdr[i].sh_addr < orgin_text_vaddr) {
                shdr[i].sh_addr += align_to_4k(vend);
            }
        }

        // start----------------------- edit .dynamic
        // 64: RELA
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                dyn = (Elf64_Dyn *)(mapped + phdr[i].p_offset);
                for (int j = 0; j < phdr[i].p_filesz / sizeof(Elf64_Dyn); j++) {
                    if (dyn[j].d_tag == DT_STRTAB |
                        dyn[j].d_tag == DT_SYMTAB |
                        dyn[j].d_tag == DT_RELA | 
                        dyn[j].d_tag == DT_JMPREL | 
                        dyn[j].d_tag == DT_VERNEED | 
                        dyn[j].d_tag == DT_VERSYM) {
                            dyn[j].d_un.d_val += align_to_4k(vend);
                    } 
                }
            }
        }
        // end------------------------- edit .dynamic

        // file layout
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (i == text_index) {
                phdr[i].p_filesz += PAGE_SIZE;
                continue;
            }
            if (phdr[i].p_offset > orgin_text_offset) {
                phdr[i].p_offset += PAGE_SIZE;
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_offset >= orgin_text_offset + orgin_text_size) {
                shdr[i].sh_offset += PAGE_SIZE;
            }
        }

        // elf节头表偏移PAGE_SIZE
        ehdr->e_shoff += PAGE_SIZE;
    }

    close(fd);
    munmap(mapped, st.st_size);

    // insert parasite code
    char *parasite_expand = malloc(PAGE_SIZE);
    memset(parasite_expand, 0, PAGE_SIZE);
    memcpy(parasite_expand, parasite, PAGE_SIZE - size > 0? size: PAGE_SIZE);
    int ret = insert_data(elfname, orgin_text_offset, parasite_expand, PAGE_SIZE);
    if (ret == 0) {
        VERBOSE("insert successfully\n");
    } else {
        VERBOSE("insert failed\n");
    }
    free(parasite_expand);

    return parasite_addr;
}

/*
                                                             
      memory layout                  file layout             
                                                             
  ─── ┌──────────────┐ 0x0000    ─── ┌──────────────┐ 0x0000 
  ▲   │  ehdr/phdr   │           ▲   │  ehdr/phdrr  │        
  │   ├──────────────┤ 0x1000    │   ├──────────────┤ 0x1000 
  │   │     TEXT     │           │   │     TEXT     │        
  │   ├──────────────┤           │   ├──────────────┤        
  │   │              │           │   │              │        
 const│              │          const│              │        
  │   │              │           │   │              │        
  │   │              │           │   │              │        
  │   │              │           │   │              │        
  │   ├──────────────┤           │   ├──────────────┤        
  ▼   │     data     │           ▼   │     data     │        
  ─── ├──────────────┤           ─── ├──────────────┤        
      │xxxxxxxxxxxxxx│               │xxxxxxxxxxxxxx│        
      └──────────────┘               ├──────────────┤        
                                     │     shdr     │        
                                     └──────────────┘        
*/

/**
 * @brief 填充text段感染
 * fill in data segments infection algorithm
 * @param elfname elf file name
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_data(char *elfname, char *parasite, size_t size) {
    int fd;
    struct stat st;
    uint8_t *mapped;
    int data_index;
    uint64_t origin_data_offset;

    uint64_t vstart, vend;
    get_segment_range(elfname, PT_LOAD, &vstart, &vend);

    fd = open(elfname, O_RDWR);
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

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;
        Elf32_Shdr *shdr;
        ehdr = (Elf32_Ehdr *)mapped;
        phdr = (Elf32_Phdr *)&mapped[ehdr->e_phoff];
        shdr = (Elf32_Shdr *)&mapped[ehdr->e_shoff];

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_vaddr + phdr[i].p_memsz == vend && phdr[i].p_type == PT_LOAD) {
                data_index = i;
                origin_data_offset = phdr[i].p_offset + phdr[i].p_filesz;
                phdr[i].p_memsz += size;
                phdr[i].p_filesz += size;
                phdr[i].p_flags |= PF_X;
                VERBOSE("expand [%d] DATA Segment, address: [0x%x], offset: [0x%x]\n", i, vend, origin_data_offset);
                break;
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_addr + shdr[i].sh_size == vend) {
                shdr[i].sh_size += size;
            }
        }

        ehdr->e_shoff += size;
    }

    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        ehdr = (Elf64_Ehdr *)mapped;
        phdr = (Elf64_Phdr *)&mapped[ehdr->e_phoff];
        shdr = (Elf64_Shdr *)&mapped[ehdr->e_shoff];

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_vaddr + phdr[i].p_memsz == vend && phdr[i].p_type == PT_LOAD) {
                data_index = i;
                origin_data_offset = phdr[i].p_offset + phdr[i].p_filesz;
                phdr[i].p_memsz += size;
                phdr[i].p_filesz += size;
                phdr[i].p_flags |= PF_X;
                VERBOSE("expand [%d] DATA Segment, address: [0x%x], offset: [0x%x]\n", i, vend, origin_data_offset);
                break;
            }
        }

        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_addr + shdr[i].sh_size == vend) {
                shdr[i].sh_size += size;
            }
        }

        ehdr->e_shoff += size;
    }

    close(fd);
    munmap(mapped, st.st_size);

    // insert parasite code
    int ret = insert_data(elfname, origin_data_offset, parasite, size);
    if (ret == 0) {
        VERBOSE("insert successfully\n");
    } else {
        VERBOSE("insert failed\n");
    }

    return vend;
}