obj-m += mimic.o

system_build_dir := /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)

# Notes on Debian hack:
#
# Debian does not ship vmlinux nor tools/bpf/resolve_btfids in
# linux-headers like Arch Linux does, so we need to refer to externally
# built one in order to build kernel module BTF successfully.
#
# Newer versions of Ubuntu does ship these files. It should not affect
# much if we apply this hack across Debian-based distros, though.

ifdef DEBIAN_HACK_RESOLVE_BTFIDS_PATH
BUILD := build
else
BUILD := $(system_build_dir)
endif

all:
ifdef DEBIAN_HACK_RESOLVE_BTFIDS_PATH
	cp -rL $(system_build_dir) $(BUILD)
	[ -f $(BUILD)/vmlinux ] || cp /sys/kernel/btf/vmlinux $(BUILD)
	[ -f $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids ] || install -Dm755 \
		$(DEBIAN_HACK_RESOLVE_BTFIDS_PATH) $(BUILD)/tools/bpf/resolve_btfids
endif
	make -C $(BUILD) M=$(PWD) modules

clean:
	rm -rf build
	[ ! -d $(system_build_dir) ] || make -C $(system_build_dir) M=$(PWD) clean
