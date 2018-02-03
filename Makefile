ifneq ($(KERNELRELEASE),)
	isgx-dummy-y := \
		sgx_main.o \
		sgx_page_cache.o \
		sgx_ioctl.o \
		sgx_vma.o \
		sgx_util.o
	obj-m += isgx-dummy.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

install: default
	$(MAKE) INSTALL_MOD_DIR=kernel/drivers/intel/sgx -C $(KDIR) M=$(PWD) modules_install
	sh -c "cat /etc/modules | grep -Fxq isgx_dummy || echo isgx_dummy >> /etc/modules"

endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
