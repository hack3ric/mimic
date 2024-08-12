include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/bpf.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/version.mk

PKG_NAME := mimic
PKG_VERSION := 0.5.0-26-g2461506
PKG_RELEASE := 1
commit := 24615062d166b0abc7ffffa2a0ac8ea298e15f3f

PKG_BUILD_DIR := $(BUILD_DIR)/mimic-$(commit)
PKG_SOURCE := $(commit).tar.gz
PKG_SOURCE_URL := https://github.com/hack3ric/mimic/archive
PKG_HASH := d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed

PKG_BUILD_DEPENDS := argp-standalone bpf-headers mimic-bpftool/host

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
	BPFTOOL="$(STAGING_DIR_HOST)/usr/sbin/mimic-bpftool" \
	BPF_TARGET="$(BPF_TARGET)" \
	LLVM_STRIP="$(LLVM_STRIP)" \
	ARGP_STANDALONE=1 \
	CHECKSUM_HACK=kprobe \
	RUNTIME_DIR=/var/run/mimic \
	STRIP_BTF_EXT=1

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
