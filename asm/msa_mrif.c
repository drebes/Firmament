/*
 * FIRMAMENT faultlet disassembler
 * Copyright (c) 2005 Roberto Jung Drebes
 *                    Leonardo Golob
 *                    Felipe Mobus
 *
 *   This file is part of FIRMAMENT.
 *
 *   FIRMAMENT is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   FIRMAMENT is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with FIRMAMENT; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include "firm_asm.h"

#define ERR_NOERR 0
#define ERR_NOMEM 1
#define ERR_OPSTR 2
#define ERR_BDPRM 3
#define ERR_BDINS 4
#define ERR_WRITE 5
#define ERR_FREAD 6
#define ERR_LABRD 7
#define ERR_BDUSE 8
#define ERR_PTBIG 9
#define ERR_BADLB 9

/* Prints usage information */
int use(char *name)
{
    printf("use:\n%s objectfile\n", name);
    printf("    or\n");
    printf("%s\n", name);
    printf("    to use implicit \"fa.out\" objectfile.\n");
    return ERR_BDUSE;
}

/* Abort. Prints error and quit. */
void die(int error, char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(error);
}


/* Gets parameters for the instruction "code" */
int findinstruct(char code, struct insttentr *instr)
{
    int i = 0;
    while (instrtable[i].name != NULL) {
	if (instrtable[i].code == code) {
	    memcpy(instr, &instrtable[i], sizeof(struct insttentr));
	    return 1;
	}
        i++;
    }
    return 0;
}



int main(int argc, char *argv[])
{

    int input;
    ssize_t i, size;
    uint16_t pos, j, strsize;
    char faultlet[UINT16_MAX + 1];
    char formatted[10];
    struct insttentr instruc;
    uint16_t shortaux;
    uint32_t wordaux;
    if (argc > 2)
	return use(argv[0]);
    input = open(argv[1] ? argv[1] : "fa.out", O_RDONLY, 0);
    if (input < 0)
	die(ERR_FREAD, "couldn't open input file %s", argv[1] ? argv[1] : "fa.out");

    pos = 0;
    size = read(input, faultlet, UINT16_MAX + 1);
    close(input);
    if (size > UINT16_MAX)
	die(ERR_FREAD, "faultlet too big.");
    while (pos < size) {
	printf("%10d  ", pos);
	if (findinstruct(faultlet[pos++], &instruc)) {
	    printf("%-6s ", instruc.name);
	    for (i = 0; i < 3; i++) {
		switch (instruc.par[i]) {
		case 0:	/* No parameter */
		    break;
		case 'R':	/* Register */
		    snprintf(formatted, 9, "R%d", faultlet[pos++]);
		    printf("%-10s ", formatted);
		    break;
		case 'S':	/* '"' delimited string */
		    printf("\"");
		    strsize = faultlet[pos++];
		    for (j = 0; j < strsize; j++) {
			switch (faultlet[pos++]) {
			case '\n':
			    printf("\\n");
			    break;
			case '\t':
			    printf("\\t");
			    break;
			case '\v':
			    printf("\\v");
			    break;
			case '\b':
			    printf("\\b");
			    break;
			case '\r':
			    printf("\\r");
			    break;
			case '\f':
			    printf("\\f");
			    break;
			case '\a':
			    printf("\\a");
			    break;
			default:
			    if (faultlet[pos - 1] < 32 || faultlet[pos - 1]
				> 126)
				printf("\\x%.3x", faultlet[pos - 1]);
			    else
				printf("%c", faultlet[pos - 1]);
			}
		    }
		    printf("\"");
		    break;
		case 'O':	/* Offset (number or symbol) */
		    memcpy(&shortaux, &faultlet[pos], sizeof(shortaux));
		    snprintf(formatted, 9, "%d", ntohs(shortaux));
		    printf("%-10s ", formatted);
		    pos += sizeof(shortaux);
		    break;
		case 'N':	/* Number (hexa or decimal) */
		    memcpy(&wordaux, &faultlet[pos], sizeof(wordaux));
		    printf("0x%.8x ", ntohl(wordaux));
		    pos += sizeof(wordaux);
		    break;

		}
	    }
	} else
	    die(ERR_BDINS, "at %d, bad instruction: 0x%x", pos,
		faultlet[pos - 1]);


	printf("\n");
    }
    return ERR_NOERR;
}
