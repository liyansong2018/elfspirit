#include "cJSON/cJSON.h"

/**
 * @brief 增加一个节
 * add a section
 * @param elfname 
 * @param size section size
 * @return int section index
 */
int add_section(char *elfname, size_t size);