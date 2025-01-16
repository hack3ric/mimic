include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/bpf.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/version.mk

PKG_NAME := mimic
PKG_VERSION := 0.6.3.20250116
PKG_RELEASE := 1

commit := 5c8cf13f28027648b8b6ec2c5581ffc47f41c1c5
PKG_BUILD_DIR := $(BUILD_DIR)/mimic-$(commit)
PKG_SOURCE := $(commit).tar.gz
PKG_SOURCE_URL := https://github.com/hack3ric/mimic/archive/
PKG_HASH := e457d84bd45f724c34670acbeb8cd4da09d929437c12c929250f9301a2d080a4

PKG_BUILD_DEPENDS := argp-standalone bpf-headers bpftool/host

# This should be added to bpftool/host upstream
PKG_BUILD_DEPENDS += binutils/host

include $(INCLUDE_DIR)/package.mk

define Package/mimic
	SECTION := net
	CATEGORY := Network
	TITLE := eBPF TCP -> UDP Obfuscator
	URL := https://github.com/hack3ric/mimic
	DEPENDS := +libbpf +libffi +kmod-sched-core +kmod-sched-bpf
endef

define KernelPackage/mimic
	SECTION := net
	SUBMENU := Network Support
	TITLE := eBPF TCP -> UDP Obfuscator - Kernel Module
	FILES := $(PKG_BUILD_DIR)/kmod/mimic.ko
endef

mimic_kmod_flags := \
	KERNEL_DIR="$(LINUX_DIR)" \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	M="$(PKG_BUILD_DIR)/kmod" \
	V="$(V)" \
	CHECKSUM_HACK=kprobe

mimic_cli_flags := \
	MODE= \
	BPF_CC="$(CLANG)" \
	BPFTOOL="$(STAGING_DIR_HOST)/usr/sbin/bpftool" \
	BPF_TARGET="$(BPF_TARGET)" \
	LLVM_STRIP="$(LLVM_STRIP)" \
	ARGP_STANDALONE=1 \
	CHECKSUM_HACK=kprobe \
	RUNTIME_DIR=/var/run/mimic \
	STRIP_BTF_EXT=1 \
	USE_LIBXDP=0

export BPF_CFLAGS := \
	-I$(BPF_HEADERS_DIR)/user_headers/include \
	-I$(STAGING_DIR)/usr/include \
	-D__MIPS$(if $(CONFIG_BIG_ENDIAN),EB,EL)__

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" $(mimic_kmod_flags) modules
	$(call Build/Compile/Default,build-cli $(mimic_cli_flags))
endef

define Package/mimic/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/out/mimic $(1)/usr/bin
endef

$(eval $(call BuildPackage,mimic))
$(eval $(call KernelPackage,mimic))
