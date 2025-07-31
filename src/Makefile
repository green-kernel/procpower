obj-m += energy_proc.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	echo 1 | sudo tee /proc/sys/kernel/sched_schedstats
	sudo insmod energy_proc.ko

uninstall:
	sudo rmmod energy_proc