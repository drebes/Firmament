#ifndef _FIRM_GLOBAL_H_
#define _FIRM_GLOBAL_H_

#define F_READB  0x00
#define F_READS  0x01
#define F_READW  0x02
#define F_WRTEB  0x03
#define F_WRTES  0x04
#define F_WRTEW  0x05
#define F_SET    0x06
#define F_ADD    0x07
#define F_SUB    0x08
#define F_MUL    0x09
#define F_DIV    0x0A
#define F_AND    0x0B
#define F_OR     0x0C
#define F_NOT    0x0D
#define F_ACP    0x0E
#define F_DRP    0x0F
#define F_DUP    0x10
#define F_DLY    0x11
#define F_JMP    0x12
#define F_JMPZ   0x13
#define F_AION   0x14
#define F_AIOFF  0x15
#define F_JMPN   0x16
#define F_CSTR   0x17
#define F_SSTR   0x18
#define F_RND    0x19
#define F_MOV    0x1A
#define F_DMP    0x1B
#define F_DBG    0x1C
#define F_VER    0x1D
#define F_SEED   0x1E

#define F_MAXREG 16
#define F_MAJORVER 0x0000
#define F_MINORVER 0x0017

#endif
