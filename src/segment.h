/*
 MIT License
 
 Copyright (c) 2024 SecNotes
 
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

/* get or set function */
enum OPT_FUNCTION {
    GET_SEG,
    SET_SEG,
    INDEX_SEG,
};

/**
 * @brief 增加一个段
 * add a segment
 * @param elf_name 
 * @param type segment type
 * @param size segment size
 * @return int segment index
 */
int add_segment(char *elf_name, int type, size_t size);

/**
 * @brief 增加一个段，并填充内容
 * add a paragraph and fill in the content
 * @param elf_name 
 * @param type segment type
 * @param content segment content
 * @param size segment size
 * @return int segment index {-1:error}
 */
int add_segment_content(char *elf_name, int type, char *content, size_t size);

/**
 * @brief 扩充一个节或者一个段，通过将节或者段移动到文件末尾实现。
 * expand a section or segment by moving it to the end of the file.
 * @param elfname 
 * @param offset sec/seg offset
 * @param org_size sec/seg origin size
 * @param add_content new added content
 * @param content_size new added content size
 * @return segment index {-1:error}
 */
int expand_segment(char *elfname, uint64_t offset, size_t org_size, char *add_content, size_t content_size);

/**
 * @brief 扩充dynstr段，通过将节或者段移动到文件末尾实现。
 * expand dynstr segment by moving it to the end of the file.
 * @param elfname 
 * @param str new dynstr item
 * @return segment index {-1:error}
 */
int expand_dynstr_segment(char *elfname, char *str);

/**
 * @brief 扩充strtab，通过将节移动到文件末尾实现。
 * expand strtab section by moving it to the end of the file.
 * @param elfname 
 * @param str new strtab item
 * @return section index {-1:error}
 */
int expand_strtab_section(char *elfname, char *str);

/**
 * @brief 添加新的hash节，通过将节移动到文件末尾实现。
 * add a new hash section by moving it to the end of the file.
 * @param elfname 
 * @param content new section content
 * @param content_size new section content size
 * @return segment index {-1:error}
 */
int add_hash_segment(char *elfname, char *content, size_t content_size);

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

/**
 * @brief 根据dynamic段的tag，得到值
 * get dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @return int error code {-1:error,0:sucess}
 */
uint64_t get_dynamic_value_by_tag(char *elfname, int tag, uint64_t *value);

/**
 * @brief 根据dynamic段的tag，得到下标
 * get dynamic segment index by tag
 * @param elfname 
 * @param tag dynamic item tag
 * @param index dynamic item index
 * @return dynamic item index {-1:error,0:sucess}
 */
uint64_t get_dynamic_index_by_tag(char *elfname, int tag, uint64_t *index);

/**
 * @brief 根据dynamic段的tag，设置值
 * set dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @return int error code {-1:error,0:sucess}
 */
uint64_t set_dynamic_value_by_tag(char *elfname, int tag, uint64_t *value);

/**
 * @brief 根据tag判断某个动态item是否存在
 * determine whether a dynamic item exists based on the tag
 * @param elfname 
 * @param tag dynamic item tag
 * @return dynamic item index {-1:false, other:true}
 */
int has_dynamic_by_tag(char *elfname, int tag);