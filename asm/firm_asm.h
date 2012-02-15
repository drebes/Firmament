#ifndef _FIRMASM_H_
#define _FIRMASM_H_

#define SYMBNUM 256
#define LABLENG 10
#define STRLENG 255
#define MAXPARM 3
#include <stdint.h>
#include "firm_global.h"

struct symbtentr {
    char name[LABLENG + 1];
    uint16_t offset;
    char used;
};

struct insttentr {
    char *name;
    char code;
    uint8_t numargs;
    uint8_t size;
    uint8_t stroper;
    char par[3];
};

struct symbtentr symboltable[SYMBNUM];

struct insttentr instrtable[] = {
    {"READB", F_READB, 2, 3, 0, {'R', 'R', 0}},
    {"READS", F_READS, 2, 3, 0, {'R', 'R', 0}},
    {"READW", F_READW, 2, 3, 0, {'R', 'R', 0}},
    {"WRTEB", F_WRTEB, 2, 3, 0, {'R', 'R', 0}},
    {"WRTES", F_WRTES, 2, 3, 0, {'R', 'R', 0}},
    {"WRTEW", F_WRTEW, 2, 3, 0, {'R', 'R', 0}},
    {"SET", F_SET, 2, 6, 0, {'N', 'R', 0}},
    {"ADD", F_ADD, 2, 3, 0, {'R', 'R', 0}},
    {"SUB", F_SUB, 2, 3, 0, {'R', 'R', 0}},
    {"MUL", F_MUL, 2, 3, 0, {'R', 'R', 0}},
    {"DIV", F_DIV, 2, 3, 0, {'R', 'R', 0}},
    {"AND", F_AND, 2, 3, 0, {'R', 'R', 0}},
    {"OR", F_OR, 2, 3, 0, {'R', 'R', 0}},
    {"NOT", F_NOT, 1, 2, 0, {'R', 0, 0}},
    {"ACP", F_ACP, 0, 1, 0, {0, 0, 0}},
    {"DRP", F_DRP, 0, 1, 0, {0, 0, 0}},
    {"DUP", F_DUP, 0, 1, 0, {0, 0, 0}},
    {"DLY", F_DLY, 1, 2, 0, {'R', 0, 0}},
    {"JMP", F_JMP, 1, 3, 0, {'O', 0, 0}},
    {"JMPZ", F_JMPZ, 2, 4, 0, {'R', 'O', 0}},
    {"AION", F_AION, 2, 3, 0, {'R', 'R', 0}},
    {"AIOFF", F_AIOFF, 1, 2, 0, {'R', 0, 0}},
    {"JMPN", F_JMPN, 2, 4, 0, {'R', 'O', 0}},
    {"CSTR", F_CSTR, 3, 4, 2, {'R', 'R', 'S'}},
    {"SSTR", F_SSTR, 2, 3, 1, {'R', 'S', 0}},
    {"RND", F_RND, 2, 3, 0, {'R', 'R', 0}},
    {"MOV", F_MOV, 2, 3, 0, {'R', 'R', 0}},
    {"DBG", F_DBG, 2, 3, 1, {'R', 'S', 0}},
    {"DMP", F_DMP, 0, 1, 0, {0, 0, 0}},
    {"VER", F_VER, 1, 2, 0, {'R', 0, 0}},
    {"SEED", F_SEED, 3, 4, 0, {'R', 'R', 'R'}},
    {NULL}

};

#endif
