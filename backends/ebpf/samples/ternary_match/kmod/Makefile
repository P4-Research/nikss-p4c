ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
obj-m  := ternary_match.o
# ternary_match-y := <other dependencies>

else
# normal makefile
KDIR ?= /lib/modules/`uname -r`/build
KMOD_DIR_INSTALL = /lib/modules/`uname -r`/extra

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
	depmod

uninstall:
	rm $(KMOD_DIR_INSTALL)/ternary_match.ko || true
	depmod

endif