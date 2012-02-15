all: firm_asm msa_mrif

firm_asm: firm_asm.c firm_asm.h
	gcc -Wall -o firm_asm firm_asm.c

msa_mrif: msa_mrif.c firm_asm.h
	gcc -Wall -o msa_mrif msa_mrif.c

clean:
	rm -rf firm_asm msa_mrif *.*~

firm_asm.h: firm_global.h
	touch firm_asm.h

