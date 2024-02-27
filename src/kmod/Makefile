obj-m += mimic.o

PWD := $(CURDIR)
DEBIAN_HACK :=

system_build_dir := /lib/modules/$(shell uname -r)/build

ifeq ($(DEBIAN_HACK), true)
BUILD := build
else
BUILD := $(system_build_dir)
endif

all:
ifeq ($(DEBIAN_HACK), true)
	cp -rL $(system_build_dir) $(BUILD)
	if [ ! -f $(BUILD)/vmlinux ]; then cp /sys/kernel/btf/vmlinux $(BUILD); fi
	if [ ! -f $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids ]; then \
		mkdir -p $(BUILD)/tools/bpf/resolve_btfids; \
		cp -r $(RESOLVE_BTFIDS_PATH) $(BUILD)/tools/bpf/resolve_btfids; \
	fi
endif
	make -C $(BUILD) M=$(PWD) modules

clean:
	rm -rf build
	make -C $(BUILD) M=$(PWD) clean
