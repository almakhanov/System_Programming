CONFIG=config.h

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m	:= ckpt.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

modules:
	echo $(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

help:
	@echo "make OPTIONS: modules help docs clean build"

config:
	rm -f $(CONFIG)
	echo "// generated by mk-config" >> $(CONFIG)
	echo >> $(CONFIG)
	./mk-config do_no_page CKPT_DO_NO_PAGE >> $(CONFIG)
	./mk-config do_swap_page CKPT_DO_SWAP_PAGE >> $(CONFIG)
	./mk-config tasklist_lock CKPT_TASKLIST_LOCK>> $(CONFIG)
	./mk-config open_namei CKPT_OPEN_NAMEI>> $(CONFIG)

build:
	make config
	make modules

docs:
	doxygen Doxyfile

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers \
	modules.order html config.h

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
