obj-m += mimic.o

system_build_dir := /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)

# Notes on Debian hack:
#
# Debian does not ship vmlinux nor resolve_btfids in
# linux-headers like Arch Linux does, so we need to refer to externally
# built one in order to build kernel module BTF successfully.
#
# Ubuntu does not ship vmlinux, but provides resolve_btfid, and there
# might be dead symlinks (e.g. rust/) inside. This needs to work around as
# well.

ifdef DEBIAN_HACK_RESOLVE_BTFIDS_PATH
BUILD := build
else
BUILD := $(system_build_dir)
endif

all:
ifdef DEBIAN_HACK_RESOLVE_BTFIDS_PATH
	cp -rs $(system_build_dir) $(BUILD)
	[ -f $(BUILD)/vmlinux ] || cp /sys/kernel/btf/vmlinux $(BUILD)
	if [ ! -f $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids ]; then \
		rm -rf tools; \
		cp -rL $(system_build_dir)/tools $(BUILD)/tools; \
		install -Dm755 $(DEBIAN_HACK_RESOLVE_BTFIDS_PATH) $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids; \
	fi
endif
	make -C $(BUILD) M=$(PWD) modules

clean:
	rm -rf build
	[ ! -d $(system_build_dir) ] || make -C $(system_build_dir) M=$(PWD) clean
