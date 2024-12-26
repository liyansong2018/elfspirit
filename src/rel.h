/**
 * @brief 得到重定位符号的偏移（其实是指地址，而非文件偏移）
 * obtain the offset of the relocation symbol (actually referring to the address, not the file offset)
 * @param h elf file struct
 * @param sec_name section name
 * @return item address {-1:error, 0:success}
 */
uint32_t get_rel32_addr(handle_t32 *h, char *sec_name, int index);
uint64_t get_rel64_addr(handle_t64 *h, char *sec_name, int index);
uint32_t get_rela32_addr(handle_t32 *h, char *sec_name, int index);
uint64_t get_rela64_addr(handle_t64 *h, char *sec_name, int index);

/**
 * @brief 得到重定位符号的符号名
 * obtain the name of the relocation symbol
 * @param h elf file struct
 * @param sec_name section name
 * @param index .rel section item index
 * @param name symbol name
 * @return error code {-1:error, 0:success}
 */
int get_rel32_name(handle_t32 *h, char *sec_name, int index, char **name);
int get_rel64_name(handle_t64 *h, char *sec_name, int index, char **name);
int get_rela32_name(handle_t32 *h, char *sec_name, int index, char **name);
int get_rela64_name(handle_t64 *h, char *sec_name, int index, char **name);

/**
 * @brief 得到重定位符号的文件偏移
 * obtain the file offset of the relocation symbol
 * @param h elf file struct
 * @param sec_name section name
 * @return item file offset {-1:error, 0:success}
 */
uint32_t get_rel32_offset(handle_t32 *h, char *sec_name, int index);
uint64_t get_rel64_offset(handle_t64 *h, char *sec_name, int index);
uint32_t get_rela32_offset(handle_t32 *h, char *sec_name, int index);
uint64_t get_rela64_offset(handle_t64 *h, char *sec_name, int index);