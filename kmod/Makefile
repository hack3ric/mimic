obj-m += mimic.o
ccflags-y := -D_MIMIC_KMOD

KERNEL_UNAME ?= $(shell uname -r)
SYSTEM_BUILD_DIR := /lib/modules/$(KERNEL_UNAME)/build

# Notes on distro hack:
#
# - Debian does not ship vmlinux nor resolve_btfids in
#   linux-headers like Arch Linux does, so we need to refer to externally
#   built one in order to build kernel module BTF successfully.
#
# - Ubuntu does not ship vmlinux, but provides resolve_btfids, and there
#   might be dead symlinks (e.g. rust/) inside. This needs to work around as
#   well.
#
# - Fedora does not provide resolve_btfids. However they ship the source code
#   of it inside /lib/modules/*.
#
# Other distributions lacking components necessary to build kernel module BTF
# can also use the hack in packaging.

ifdef DISTRO_HACK

build_dir := build

VMLINUX_DISTRO_HACK ?= /usr/lib/mimic/vmlinux-distro-hack
RESOLVE_BTFIDS ?= /usr/lib/mimic/resolve_btfids

export EXTRACT_VMLINUX ?= /usr/lib/mimic/extract-vmlinux
export EXTRACT_BTF ?= /usr/lib/mimic/extract-btf
export VMLINUX_SUFFIX ?= -$(KERNEL_UNAME)

else
build_dir := $(SYSTEM_BUILD_DIR)
endif

all:
ifdef DISTRO_HACK
	cp -rL $(SYSTEM_BUILD_DIR) $(build_dir) || true
	$(VMLINUX_DISTRO_HACK) $(build_dir)
	if [ ! -f $(build_dir)/tools/bpf/resolve_btfids/resolve_btfids ]; then \
		install -Dm755 $(RESOLVE_BTFIDS) $(build_dir)/tools/bpf/resolve_btfids/resolve_btfids; \
	fi
endif
	$(MAKE) -C $(build_dir) M=$(CURDIR) modules

clean:
ifdef DISTRO_HACK
	rm -rf $(build_dir)
endif
	[ ! -d $(SYSTEM_BUILD_DIR) ] || $(MAKE) -C $(SYSTEM_BUILD_DIR) M=$(CURDIR) clean
