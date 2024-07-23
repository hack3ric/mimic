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

ifdef DEBIAN_HACK
BUILD := build
else
BUILD := $(SYSTEM_BUILD_DIR)
endif

all:
ifdef DEBIAN_HACK
	cp -rL $(SYSTEM_BUILD_DIR) $(BUILD) || true

	if [ -f $(BUILD)/vmlinux ]; then \
		if [ -f /boot/vmlinuz-$(KERNEL_UNAME) ]; then \
			/usr/lib/mimic/extract-vmlinux /boot/vmlinuz-$(KERNEL_UNAME) > $(BUILD)/vmlinux; \
			[ $? -eq 0 ] || /usr/lib/mimic/extract-btf /boot/vmlinuz-$(KERNEL_UNAME) > $(BUILD)/vmlinux; \
			if [ $? -ne 0 ]; then \
				echo ERROR: cannot extract BTF from boot image; \
				exit 1; \
			fi \
		elif [ -f /boot/vmlinux-$(KERNEL_UNAME) ]; then \
			/usr/lib/mimic/extract-btf /boot/vmlinux-$(KERNEL_UNAME) > $(BUILD)/vmlinux; \
			if [ $? -eq 0 ]; then \
				echo ERROR: cannot extract BTF from boot image; \
				exit 1; \
			fi \
		else \
			echo ERROR: no boot image found; \
			exit 1; \
		fi \
	fi

	[ -f $(BUILD)/vmlinux ] || /usr/lib/mimic/extract-vmlinux /boot/vmlinuz-$(KERNEL_UNAME) > $(BUILD)/vmlinux

	if [ ! -f $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids ]; then \
		install -Dm755 /usr/lib/mimic/resolve_btfids $(BUILD)/tools/bpf/resolve_btfids/resolve_btfids; \
	fi
endif
	$(MAKE) -C $(BUILD) M=$(PWD) modules

clean:
	rm -rf build
	[ ! -d $(SYSTEM_BUILD_DIR) ] || $(MAKE) -C $(SYSTEM_BUILD_DIR) M=$(PWD) clean
