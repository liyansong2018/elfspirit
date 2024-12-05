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

#include "cJSON/cJSON.h"

/**
 * @brief 得到段的映射地址范围
 * Obtain the mapping address range of the segment
 * @param elf_name 
 * @param type segment type
 * @param start output args
 * @param end output args
 * @return int error code {-1:error,0:sucess}
 */
int get_segment_range(char *elf_name, int type, uint64_t *start, uint64_t *end);

/**
 * @brief 增加一个段
 * add a segment
 * @param elf_name 
 * @param type segment type
 * @param start segment size
 * @return int segment index
 */
int add_segment(char *elf_name, int type, size_t size);

/**
 * @brief 根据段的下标，获取段的偏移
 * obtain the offset of the segment based on its index
 * @param elfname 
 * @param i segment index
 * @return uint64_t segment offset
 */
uint64_t get_segment_offset(char *elfname, int i);
uint64_t get_segment_vaddr(char *elfname, int i);
uint64_t get_segment_paddr(char *elfname, int i);
uint64_t get_segment_filesz(char *elfname, int i);
uint64_t get_segment_memsz(char *elfname, int i);
uint64_t get_segment_type(char *elfname, int i);
uint64_t get_segment_flags(char *elfname, int i);
uint64_t get_segment_align(char *elfname, int i);