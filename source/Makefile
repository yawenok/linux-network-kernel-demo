ifneq ($(KERNELRELEASE))

#模块名称与主文件netfilter.o保持一致
MODULE_NAME := netfilter

#模块主文件netfilter.o.c
CORE_OBJS := netfilter.o.o

#添加包含的C文件 file1.o file2.o
#INCLUE_OBJS := file1.o file2.o

#$(INCLUE_OBJS),多文件添加到下面
$(MODULE_NAME)-objs := $(CORE_OBJS)

obj-m := $(CORE_OBJS)

else

PWD := $(shell pwd)

KDIR := /usr/src/linux-headers-3.13.0-32-generic

all:
		$(MAKE) -C $(KDIR) M=$(PWD)
clean:
		rm -rf *.mod.c *.mod.o *.ko *.o *.tmp_versions *.order *symvers
endif
