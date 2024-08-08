obj-m += mimic.o
mimic-objs := main.o
ccflags-y := -D_MIMIC_KMOD

KERNEL_UNAME ?= $(shell uname -r)
SYSTEM_BUILD_DIR := /lib/modules/$(KERNEL_UNAME)/build

CHECKSUM_HACK ?= kfunc
ifeq ($(filter kfunc kprobe,$(CHECKSUM_HACK)),)
$(error unknown checksum hack '$(CHECKSUM_HACK)')
endif
mimic-objs += csum-hack-$(CHECKSUM_HACK).o
ccflags-y += -DMIMIC_CHECKSUM_HACK_$(CHECKSUM_HACK)

# Notes on hack:
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

ifneq ($(wildcard $(SYSTEM_BUILD_DIR)/vmlinux),)
vmlinux_exists := 1
else
vmlinux_exists := 0
endif
ifneq ($(wildcard $(SYSTEM_BUILD_DIR)/tools/bpf/resolve_btfids/resolve_btfids),)
resolve_btfids_exists := 1
else
resolve_btfids_exists := 0
endif

ifeq ($(vmlinux_exists)$(resolve_btfids_exists),11)
build_dir := $(SYSTEM_BUILD_DIR)
else
enable_hack := 1
build_dir := build

RESOLVE_BTFIDS ?= /usr/lib/mimic/resolve_btfids

path_extension := PATH="$$PATH:/usr/lib/mimic:$(CURDIR)/../out:$(CURDIR)/../tools"
VMLINUX_TO_BTF ?= $(path_extension) vmlinux-to-btf
export EXTRACT_VMLINUX ?= $(path_extension) extract-vmlinux
export EXTRACT_BTF ?= $(path_extension) extract-btf
export VMLINUX_SUFFIX ?= -$(KERNEL_UNAME)

endif

all: build

.PHONY: build
build:
ifdef enable_hack
	-cp -rL $(SYSTEM_BUILD_DIR) $(build_dir)
ifeq ($(vmlinux_exists),0)
	$(VMLINUX_TO_BTF) >$(build_dir)/vmlinux
endif
ifeq ($(resolve_btfids_exists),0)
ifeq ($(wildcard $(RESOLVE_BTFIDS)),)
	@echo "ERROR: `resolve_btfids` not found; please compile it from Linux kernel source and re-run make with RESOLVE_BTFIDS=<path>"
	@exit 1
endif
	install -Dm755 $(RESOLVE_BTFIDS) $(build_dir)/tools/bpf/resolve_btfids/resolve_btfids
endif  # resolve_btfids_exists
endif  # enable_hack
	$(MAKE) -C $(build_dir) M=$(CURDIR) modules

.PHONY: clean
clean:
	rm -rf build dkms.conf AKMBUILD
	[ ! -d $(SYSTEM_BUILD_DIR) ] || $(MAKE) -C $(SYSTEM_BUILD_DIR) M=$(CURDIR) clean

dkms.conf: dkms.conf.in
	sed 's|@@EXTRA_OPTS@@|CHECKSUM_HACK=$(CHECKSUM_HACK)|' $^ > $@
AKMBUILD: AKMBUILD.in
	sed 's|@@EXTRA_OPTS@@|CHECKSUM_HACK=$(CHECKSUM_HACK)|' $^ > $@
