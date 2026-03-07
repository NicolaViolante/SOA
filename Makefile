obj-m += the_throttler.o

ccflags-y := -I$(src)/header

the_throttler-objs := throttler_main.o \
                      throttler_memory.o \
                      throttler_core.o \
                      throttler_hook.o \
                      throttler_config.o \
                      throttler_chrdev.o \
                      throttler_ioctl.o \
                      lib/vtpmo.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
