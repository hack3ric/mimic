obj-m += mimic.o

PWD := $(CURDIR)
BUILD := /lib/modules/$(shell uname -r)/build

all:
	make -C $(BUILD) M=$(PWD) modules

clean:
	make -C $(BUILD) M=$(PWD) clean
