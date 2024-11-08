/*
 MIT License
 
 Copyright (c) 2021 Yansong Li
 
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

/* ELF parser options */
#ifndef __PARSE_H
#define __PARSE_H
typedef enum PARSE_OPT {
    ALL = 1,
    HEADERS,
    SECTIONS,
    SEGMENTS,
    SYMTAB,
    DYNSYM,
    LINK,
    RELA,
    END
} PARSE_OPT_T;

typedef struct parser_opt {
    char options[END];
    int index;
} parser_opt_t;
#endif

int parse(char *elf, parser_opt_t *po);

/**
 * @description: Judge whether the option is true
 * @param {parser_opt_t} po
 * @param {PARSE_OPT_T} option
 * @return {*}
 */
int get_option(parser_opt_t *po, PARSE_OPT_T option);
