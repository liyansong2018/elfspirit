/* 重新计算hash表 */
/* Mainly inspired from LIEF */
int set_hash_table32(char *elf_name);
int set_hash_table64(char *elf_name);
/* refresh gnu hash table */
int refresh_hash_table(char *elf_name);