obj-m += mimic.o

system_build_dir := /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)

ifdef DEBIAN_HACK_RESOLVE_BTFIDS_PATH
BUILD := build
else
BUILD := $(system_build_dir)
endif

all:
ifdef DEBIAN_HACK_RESOLVE_BTFIDS_PATH
	cp -rL $(system_build_dir) $(BUILD)
	if [ ! -f $(BUILD)/vmlinux ]; then cp /sys/kernel/btf/vmlinux $(BUILD); fi
	if [ ! -f $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids ]; then \
		mkdir -p $(BUILD)/tools/bpf/resolve_btfids; \
		cp -r $(DEBIAN_HACK_RESOLVE_BTFIDS_PATH) $(BUILD)/tools/bpf/resolve_btfids; \
	fi
endif
	make -C $(BUILD) M=$(PWD) modules

clean:
	rm -rf build
	make -C $(BUILD) M=$(PWD) clean
