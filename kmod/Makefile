obj-m += mimic.o

KERNEL_UNAME ?= $(shell uname -r)

SYSTEM_BUILD_DIR := /lib/modules/$(KERNEL_UNAME)/build
PWD := $(CURDIR)

ccflags-y := -D_MIMIC_KMOD

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
BUILD := $(SYSTEM_BUILD_DIR)
endif

all:
ifdef DEBIAN_HACK_RESOLVE_BTFIDS_PATH
	cp -rL $(SYSTEM_BUILD_DIR) $(BUILD) || true
	[ -f $(BUILD)/vmlinux ] || /usr/lib/mimic/extract-vmlinux /boot/vmlinuz-$(KERNEL_UNAME) > $(BUILD)/vmlinux
	if [ ! -f $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids ]; then \
		install -Dm755 $(DEBIAN_HACK_RESOLVE_BTFIDS_PATH) $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids; \
	fi
endif
	$(MAKE) -C $(BUILD) M=$(PWD) modules

clean:
	rm -rf build
	[ ! -d $(SYSTEM_BUILD_DIR) ] || $(MAKE) -C $(SYSTEM_BUILD_DIR) M=$(PWD) clean
