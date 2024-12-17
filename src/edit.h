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

/**
 * @brief Set the section name
 * 
 * @param elf_name elf file name
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_header_type(char *elf_name, int value);
int set_header_machine(char *elf_name, int value);
int set_header_version(char *elf_name, int value);
int set_header_entry(char *elf_name, int value);
int set_header_phoff(char *elf_name, int value);
int set_header_shoff(char *elf_name, int value);
int set_header_flags(char *elf_name, int value);
int set_header_ehsize(char *elf_name, int value);
int set_header_phentsize(char *elf_name, int value);
int set_header_phnum(char *elf_name, int value);
int set_header_shentsize(char *elf_name, int value);
int set_header_shnum(char *elf_name, int value);
int set_header_shstrndx(char *elf_name, int value);

/**
 * @brief Set the section name
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_section_name(char *elf_name, int index, int value);
int set_section_type(char *elf_name, int index, int value);
int set_section_flags(char *elf_name, int index, int value);
int set_section_addr(char *elf_name, int index, int value);
int set_section_off(char *elf_name, int index, int value);
int set_section_size(char *elf_name, int index, int value);
int set_section_link(char *elf_name, int index, int value);
int set_section_info(char *elf_name, int index, int value);
int set_section_align(char *elf_name, int index, int value);
int set_section_entsize(char *elf_name, int index, int value);

int set_section_name_by_str(char *elf_name, int index, char *value);

/**
 * @brief Set the segment type
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_type(char *elf_name, int index, int value);
int set_segment_flags(char *elf_name, int index, int value);
int set_segment_offset(char *elf_name, int index, int value);
int set_segment_vaddr(char *elf_name, int index, int value);
int set_segment_paddr(char *elf_name, int index, int value);
int set_segment_filesz(char *elf_name, int index, int value);
int set_segment_memsz(char *elf_name, int index, int value);
int set_segment_align(char *elf_name, int index, int value);

/**
 * @brief Set the dynsym or symtab object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_sym_name(char *elf_name, int index, int value, char *section_name);
int set_sym_value(char *elf_name, int index, int value, char *section_name);
int set_sym_size(char *elf_name, int index, int value, char *section_name);
int set_sym_type(char *elf_name, int index, int value, char *section_name);
int set_sym_bind(char *elf_name, int index, int value, char *section_name);
int set_sym_other(char *elf_name, int index, int value, char *section_name);
int set_sym_shndx(char *elf_name, int index, int value, char *section_name);

/**
 * @brief Set the .rela section offset
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_rela_offset(char *elf_name, int index, int value, char *section_name);
int set_rela_info(char *elf_name, int index, int value, char *section_name);
int set_rela_type(char *elf_name, int index, int value, char *section_name);
int set_rela_index(char *elf_name, int index, int value, char *section_name);
int set_rela_addend(char *elf_name, int index, int value, char *section_name);
/* .rel.* */
int set_rel_offset(char *elf_name, int index, int value, char *section_name);
int set_rel_info(char *elf_name, int index, int value, char *section_name);
int set_rel_type(char *elf_name, int index, int value, char *section_name);
int set_rel_index(char *elf_name, int index, int value, char *section_name);

/**
 * @brief Set the .dynamic section offset
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_dyn_tag(char *elf_name, int index, int value);
int set_dyn_value(char *elf_name, int index, int value);

/**
 * @brief Set the dynsym name by str object
 * 
 * @param elf_name elf file name
 * @param index elf file name
 * @param name string value to be edited
 * @param section_name .dynsym or .symtab
 * @param str_section_name .dynstr or .strtab
 * @return int 
 */
int edit_sym_name_string(char *elf_name, int index, char *name, char *section_name, char *str_section_name);
int edit_dyn_name_value(char *elf_name, int index, char *name);

int edit(char *elf, parser_opt_t *po, int row, int column, int value, char *section_name, char *file_name);