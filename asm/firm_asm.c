/*
 * FIRMAMENT faultlet assembler
 * Copyright (c) 2005 Roberto Jung Drebes
 *                    Leonardo Golob
 *                    Felipe Mobus 
 *
 * Portions of this code (in stringparse, tokenize) 
 * Copyright (c) 1991 Phil Karn, KA9Q
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
#define ERR_BDSTR 2
#define ERR_BDPRM 3
#define ERR_BDINS 4
#define ERR_WRITE 5
#define ERR_FREAD 6
#define ERR_LABRD 7
#define ERR_BDUSE 8
#define ERR_PTBIG 9
#define ERR_BADLB 9

/* Global line number for error reporting */
uint32_t lineno;

/* Print usage information */
int use(char *name)
{
    printf("use: %s assemblyfile [objectfile]\n", name);
    return ERR_BDUSE;
}

/* Abort. Print error and quit. */
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

/* Print symbols (labels) used */
void printsymbols(void)
{
    int i;
    printf("symbol table:\n");
    for (i = 0; i < SYMBNUM; i++) {
	if (symboltable[i].used)
	    printf("%-20s %-5d \n", symboltable[i].name,
		   symboltable[i].offset);
    }
    printf("\n");
};

/* Hash function */
uint8_t hash(char *str)
{
    uint8_t c;
    int i = 1;
    c = tolower(str[0]);
    while (tolower(str[i])) {
	c = c ^ tolower(str[i++]);
    };
    return (c % SYMBNUM);
}

/*
 * Read a text line from 'fd'. Allocate memory as needed.
 * Memory should be manually freed after use.
 */
char *readline(int fd)
{
    ssize_t readno, allocno, readok;
    char *line, thechar;

    readno = 0;
    allocno = 80;
    line = malloc(allocno);
    if (!line)
	die(ERR_NOMEM, "memory full.");
    readok = read(fd, &thechar, 1);
    while (thechar != '\n' && thechar != '\r' && readok) {
	readno++;
	if (readno >= allocno) {
	    allocno = allocno + 40;
	    line = realloc(line, allocno);
	    if (!line)
		die(ERR_NOMEM, "memory full.");
	}
	line[readno - 1] = thechar;
	readok = read(fd, &thechar, 1);
    }
    line[readno] = '\0';
    if (readok)
	return line;
    else {
	free(line);
	return NULL;
    }
}

/* Initialize global variables */
void init(void)
{
    int i;
    lineno = 0;
    for (i = 0; i < SYMBNUM; i++)
	symboltable[i].used = 0;
}

/* Add a symbol to the symbol table */
int addsymbol(struct symbtentr *e)
{
    uint8_t pos, st_pos;

    st_pos = pos = hash(e->name);
    do {
	if (!symboltable[pos].used) {
	    memcpy(&symboltable[pos], e, sizeof(struct symbtentr));
	    symboltable[pos].used = 1;
	    return 1;
	} else {
	    if (!strcasecmp(symboltable[pos].name, e->name))
		return 0;
	}
	pos = (pos + 1) % SYMBNUM;
    } while (pos != st_pos);

    return 0;
}

/* Get parameters for the symbol (label) "name". */
int findsymbol(char *name, struct symbtentr *e)
{
    uint8_t pos, st_pos;

    st_pos = pos = hash(name);

    do {
	if (symboltable[pos].used) {
	    if (!strcasecmp(symboltable[pos].name, name)) {
		memcpy(e, &symboltable[pos], sizeof(struct symbtentr));
		return 1;
	    } else {
		pos = (pos + 1) % SYMBNUM;
	    }
	} else
	    return 0;

    } while (pos != st_pos);

    return 0;
}

/* Get parameters for the instruction "name" */
int findinstruct(char *name, struct insttentr *instr)
{
    int i = 0;
    while (instrtable[i].name != NULL) {
	if (!strcasecmp(instrtable[i].name, name)) {
	    memcpy(instr, &instrtable[i], sizeof(struct insttentr));
	    return 1;
	}
        i++;
    }
    return 0;
}

/* Convert string to long, return wether the conversion succeeded. */
int isanumber(char *name, int32_t * value, int base, int sign)
{
    char *err;
    if (sign)
	*value = strtol(name, &err, base);
    else
	*value = strtoul(name, &err, base);
    if (*err != '\0')
	return 0;
    else
	return 1;
}

/*
 * Assemble the instruction "instruc", using the given
 * parameters. Allocate memory as needed.
 * Memory should be manually freed after use.
 */
char *assemble(struct insttentr instruc, char *oper[], ssize_t * bytes)
{
    ssize_t i, j, k;
    char *assembly;
    struct symbtentr e;
    int32_t number;
    uint32_t strsize;
    uint16_t shortaux;
    uint8_t ishex;

    i = 0;
    assembly = malloc(STRLENG + 4);
    assembly[i++] = instruc.code;
    for (j = 0; j < MAXPARM; j++) {

	switch (instruc.par[j]) {
	case 0:		/* No parameter */
	    if (oper[j])
		die(ERR_BDPRM,
		    "line %d, unexpected parameter: %s", lineno, oper[j]);
	    break;
	case 'R':		/* Register */
	    if (!oper[j])
		die(ERR_BDPRM,
		    "line %d, expected register missing as parameter %d.",
		    lineno, j + 1);
	    if ((strncasecmp(oper[j], "r", 1))
		|| (!isanumber(oper[j] + 1, &number, 10, 0))
		|| (number > F_MAXREG)
		|| (number < 0))
		die(ERR_BDPRM, "line %d, bad register %s",
		    lineno, oper[j]);
	    assembly[i++] = 0x00ff & number;
	    break;
	case 'S':		/* quote delimited string */
	    if (!oper[j])
		die(ERR_BDPRM,
		    "line %d, expected string missing as parameter %d.",
		    lineno, j + 1);
	    if (strncmp(oper[j], "\"", 1))
		die(ERR_BDPRM, "line %d, bad string: %s", lineno, oper[j]);
	    strsize = strlen(oper[j]) - 1;	/* exclude the '"'s */// menos 1
	    if (strsize > STRLENG)
		die(ERR_BDPRM,
		    "line %d, string too long: %s", lineno, oper[j]);
	    assembly[i++] = strsize;
	    for (k = 1; k <= strsize; k++)
		assembly[i++] = oper[j][k];
	    break;
	case 'O':		/* Offset (number or symbol) */
	    if (!oper[j])
		die(ERR_BDPRM,
		    "line %d, expected offset missing as parameter %d.",
		    lineno, j + 1);
	    strcpy(e.name, "");
	    ishex = !strncmp(oper[j], "0x", 2);
	    if (((!isanumber
		  (oper[j], &number, ishex ? 16 : 10, ishex ? 0 : 1))
		 && (!findsymbol(oper[j], &e))) || (number < 0)
		|| (number > UINT16_MAX))
		die(ERR_BDPRM, "line %d, bad offset: %s", lineno, oper[j]);
	    if (strlen(e.name))
		shortaux = htons(e.offset);
	    else
		shortaux = htons(number & 0xffff);
	    memcpy(assembly + i, &shortaux, sizeof(uint16_t));
	    i += sizeof(uint16_t);
	    break;
	case 'N':		/* Number (hex or decimal) */
	    if (!oper[j])
		die(ERR_BDPRM,
		    "line %d, expected number missing as parameter %d.",
		    lineno, j + 1);
	    ishex = !strncmp(oper[j], "0x", 2);
	    if ((!isanumber
		 (oper[j], &number, ishex ? 16 : 10, ishex ? 0 : 1)))
		die(ERR_BDPRM, "line %d, bad number: %s", lineno, oper[j]);
	    number = htonl(number);
	    memcpy(assembly + i, &number, sizeof(number));
	    i += sizeof(number);
	    break;
	}

    }
    *bytes = i;
    return assembly;
}

/* Get label, operation and paramters from pargv[] */
void getall(char **label, char **operation, char *npar[MAXPARM], int pargc,
	    char *pargv[])
{
    int i, haslabel = 0;
    *label = NULL;
    *operation = NULL;
    for (i = 0; i < 3; i++)
	npar[i] = NULL;

    if (pargc) {
	/* Line is not empty */
	if (pargv[0][strlen(pargv[0]) - 1] == ':') {
	    /* Found a label as first token */
	    *label = pargv[0];
	    (*label)[strlen(*label) - 1] = '\0';
	    if (strlen(*label) > LABLENG)
		die(ERR_BADLB, "line %d, label too long.", lineno);
	    haslabel = 1;
	}
	if (!haslabel)
	    /* Found operation as first token */
	    *operation = pargv[0];
	else if (pargc > 1)
	    /* Has label. operation is second token */
	    *operation = pargv[1];
	else
	    /* No operation */
	    *operation = NULL;
	if (pargc > MAXPARM + 1 + haslabel)
	    die(ERR_BDPRM, "line %d, too many parameters.", lineno);

	/* Copy remaining parameters */
	for (i = 1 + haslabel; i < pargc; i++)
	    npar[i - (1 + haslabel)] = pargv[i];
    }
}

/*
 * Parse a quoted string. Do not remove the opening quote (it is used by 
 * assemble(), but remove the trailing one, to give room to a '\0' before
 * a comment right after the closing quote ("like";this).
 */
static char *stringparse(char *line)
{
    char *cp = line;
    unsigned long num;
    /* Accept the first quote */
    *cp++ = *line++;
    /* Until the line or string ends */
    while (*line != '\0' && *line != '\"') {
	/* Escaped sequences */
	if (*line == '\\') {
	    line++;
	    switch (*line++) {
	    case 'n':
		*cp++ = '\n';
		break;
	    case 't':
		*cp++ = '\t';
		break;
	    case 'v':
		*cp++ = '\v';
		break;
	    case 'b':
		*cp++ = '\b';
		break;
	    case 'r':
		*cp++ = '\r';
		break;
	    case 'f':
		*cp++ = '\f';
		break;
	    case 'a':
		*cp++ = '\a';
		break;
	    case '\\':
		*cp++ = '\\';
		break;
	    case '\?':
		*cp++ = '\?';
		break;
	    case '\'':
		*cp++ = '\'';
		break;
	    case '\"':
		*cp++ = '\"';
		break;
		/* Hex number */
	    case 'x':
		num = strtoul(line, &line, 16);
		/* Die on null character on string */
		if (num == 0)
		    die(ERR_BDSTR,
			"line %d, null character in string.", lineno);
		*cp++ = (char) num;
		break;
		/* Octal number */
	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
		line--;
		num = strtoul(line, &line, 8);
		/* Die on null character on string */
		if (num == 0)
		    die(ERR_BDSTR,
			"line %d, null character in string.", lineno);
		*cp++ = (char) num;
		break;
	    case '\0':
		/* Die on null character on string */
		die(ERR_BDSTR,
		    "line %d, null character in string.", lineno);
	    default:
		*cp++ = *(line - 1);
		break;
	    };
	} else {
	    *cp++ = *line++;
	}
    }
    /* If final character is not quote, die with unterminated string  */
    if (*line != '\"')
	die(ERR_BDSTR, "line %d, unmatched '\"'.", lineno);
    /* Terminate string */
    *(cp) = '\0';
    /* Update line to search for the next token */
    line++;
    return line;
}

/*
 * Receive a null terminated string 'line' and fill argc with the
 * token count and argv[] with the list of tokens. maxargc is the
 * maximum number of tokens expected by the calling function.
 */
void tokenize(char *line, int *argc, char *argv[], int maxargc)
{
    char *cp, *comment, *space, *tab, *whitespace;

    /* Initialize token list */
    for (*argc = 0; *argc < maxargc; (*argc)++)
	argv[*argc] = NULL;

    for (*argc = 0; *argc < maxargc;) {
	int qflag = 0;
	/* Skip leading white space */
	while (isspace(*line))
	    line++;
	if (*line == '\0' || *line == ';')
	    /* Line ended */
	    break;
	/* Check for quoted token */
	if (*line == '"') {
	    /* 
	     * Enter quote mode. Quote is *not* suppresed, since its used
	     * by assemble() to check paramters. 
	     */
	    qflag = 1;
	}
	/* Start of token */
	argv[(*argc)++] = line;

	if (qflag) {
	    /* Find terminating delimiter */
	    line = stringparse(line);
	} else {
	    /*
	     * We should jump to the next space, tab or comment character,
	     * but the one that appears first. If we find none, we are at the
	     * last token.
	     */
	    space = strchr(line, ' ');
	    tab = strchr(line, '\t');
	    comment = strchr(line, ';');
	    if (!space && !tab && !comment)
		/* None found, return */
		break;
	    if (space && !tab)
		whitespace = space;
	    if (!space && tab)
		whitespace = tab;
	    if (space && tab) {
		if (space < tab)
		    whitespace = space;
		else
		    whitespace = tab;
	    }
	    if (comment) {
		/* Comment exists. */
		if (whitespace) {
		    /* Is if before or after whitespace? */
		    if (comment < whitespace)
			cp = comment;
		    else
			cp = whitespace;
		} else
		    cp = comment;
	    } else
		cp = whitespace;
	    /*
	     * If we found a comment char (right after a string),
	     * remove it and we are done.
	     */
	    if (*cp == ';') {
		*cp = '\0';
		break;
	    }
	    /* Whitespace. Close this token here, and try next. */
	    *cp++ = '\0';
	    line = cp;
	}
    }
}

/*
 * Main function. Open input, get label offsets, open output,
 * then assemble.
 */
int main(int argc, char *argv[])
{

    int input, output;
    char *line, *assembly;
    char *label, *operation;
    ssize_t size = 0, isize, wrote, pos;
    struct insttentr instruc;
    struct symbtentr symbol;
    int pargc;
    char faultlet[UINT16_MAX];
    char *pargv[6];
    char *npar[MAXPARM];

    init();
    if ((argv[1] == NULL) || (argc > 3))
	return use(argv[0]);
    input = open(argv[1], O_RDONLY, 0);
    if (input < 0)
	die(ERR_FREAD, "couldn't open input file %s", argv[1]);
    pos = 0;
    while ((line = readline(input))) {
	lineno++;
	tokenize(line, &pargc, pargv, 6);
	getall(&label, &operation, npar, pargc, pargv);
	if (label) {
	    strcpy(symbol.name, label);
	    symbol.offset = pos;
	    if (!addsymbol(&symbol))
		die(ERR_LABRD,
		    "line %d, label redefined: %s", lineno, label);
	}
	if (operation) {
	    if (findinstruct(operation, &instruc)) {
		if (instruc.stroper)
		    pos += (instruc.size + strlen(npar[instruc.stroper]) - 1);	/* excluding opening quote */
		else
		    pos += instruc.size;
		if (pos > UINT16_MAX)
		    die(ERR_PTBIG, "program too big.");
	    } else {
		die(ERR_BDINS,
		    "line %d, bad instruction: %s", lineno, operation);
	    }
	}
	free(line);
    }
    close(input);
    lineno = 0;
    input = open(argv[1], O_RDONLY, 0);
    if (input < 0)
	die(ERR_FREAD, "couldn't open input file %s", argv[1]);
    while ((line = readline(input))) {
	lineno++;
	tokenize(line, &pargc, pargv, 6);
	getall(&label, &operation, npar, pargc, pargv);
	if (operation) {
	    if (findinstruct(operation, &instruc)) {
		assembly = assemble(instruc, npar, &isize);
		memcpy(&faultlet[size], assembly, isize);
		size += isize;
		free(assembly);
	    } else {
		die(ERR_BDINS,
		    "line %d, bad instruction: %s", lineno, operation);
	    }
	}
	free(line);
    }
    close(input);
    if (argv[2] == NULL)
	output = creat("fa.out", 0700);
    else
	output = creat(argv[2], 0700);
    if (output < 0)
	die(ERR_WRITE, "couldn't write to output file %s",
	    argv[2] ? argv[2] : "fa.out");
    wrote = write(output, faultlet, size);
    if (wrote < size)
	die(ERR_WRITE, "couldn't write to output file %s",
	    argv[2] ? argv[2] : "fa.out");
    close(output);
    return ERR_NOERR;
}
