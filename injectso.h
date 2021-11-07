/*
 * @Author: your name
 * @Date: 2021-10-26 16:35:11
 * @LastEditTime: 2021-11-02 11:34:57
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /elf/injectso.h
 */

/**
 * @description: Modify the content of a section of elf to load so (修改elf某个节的内容用于加载so)
 * @param {char} *elf_name
 * @param {char} *modify_sec_name
 * @param {char} *so_name
 * @param {char} *json_name file contains libc/ld offset
 * @param {char} *version libc or ld version
 * @return {*}
 */
int inject_so(char *elf_name, char *modify_sec_name, char *so_name, char *json_name, char *version);