KSRC=/lib/modules/`uname -r`/build

obj-m = firm_vm.o

all: build

build:
	make -C $(KSRC) SUBDIRS=`pwd` modules

install:
	@# completely broken ATM - removes the whole dir
	@#make -C $(KSRC) SUBDIRS=`pwd` modules_install
	@echo "Install it yourself ..."

clean:
	@# kbuild can't handle this (yet ?)
	@#make -C $(KSRC) SUBDIRS=`pwd` clean
	rm -Rf *.o *.ko *.mod.o *.mod.c .*.{cmd,flags} *.*~ .tmp_versions 
