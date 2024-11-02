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
 * @brief Set the dynsym name object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_dynsym_name(char *elf_name, int index, int value, char *section_name);
int set_dynsym_value(char *elf_name, int index, int value, char *section_name);
int set_dynsym_size(char *elf_name, int index, int value, char *section_name);
int set_dynsym_type(char *elf_name, int index, int value, char *section_name);
int set_dynsym_bind(char *elf_name, int index, int value, char *section_name);
int set_dynsym_other(char *elf_name, int index, int value, char *section_name);
int set_dynsym_shndx(char *elf_name, int index, int value, char *section_name);

int edit(char *elf, parser_opt_t *po, int row, int column, int value);