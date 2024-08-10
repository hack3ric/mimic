#
# Copyright (C) 2020-2024 Tony Ambardar <itugrok@yahoo.com>
# Copyright (C) 2024 Eric Long <i@hack3r.moe>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

# Modified bpftool Makefile that builds itself as host tool, used in 
# building Mimic.

include $(TOPDIR)/rules.mk

PKG_NAME:=mimic-bpftool
PKG_VERSION:=7.4.0
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/libbpf/bpftool
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=v7.4.0

PKG_MAINTAINER:=Tony Ambardar <itugrok@yahoo.com>, \
	Eric Long <i@hack3r.moe>

PKG_BUILD_FLAGS:=no-mips16 gc-sections lto
PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

HOST_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk
include $(INCLUDE_DIR)/host-build.mk

define Package/mimic-bpftool/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bpftool - eBPF subsystem utility
  LICENSE:=GPL-2.0-only OR BSD-2-Clause
  URL:=http://www.kernel.org
  DEPENDS:=+libelf
endef

define Package/mimic-bpftool-minimal
  $(call Package/mimic-bpftool/Default)
  TITLE+= (Minimal)
  VARIANT:=minimal
  DEFAULT_VARIANT:=1
  PROVIDES:=bpftool
  ALTERNATIVES:=200:/usr/sbin/bpftool:/usr/libexec/bpftool-minimal
endef

define Package/mimic-bpftool-full
  $(call Package/mimic-bpftool/Default)
  TITLE+= (Full)
  VARIANT:=full
  PROVIDES:=bpftool
  ALTERNATIVES:=300:/usr/sbin/bpftool:/usr/libexec/bpftool-full
  DEPENDS+= +libbfd +libopcodes
endef

define Package/mimic-bpftool-minimal/description
  A tool for inspection and simple manipulation of eBPF programs and maps.
endef

define Package/mimic-bpftool-full/description
  A tool for inspection and simple manipulation of eBPF programs and maps.
  This full version uses libbfd and libopcodes to support disassembly of
  eBPF programs and jited code.
endef

TARGET_CFLAGS += -ffunction-sections -fdata-sections -flto
TARGET_LDFLAGS += -Wl,--gc-sections -flto

ifeq ($(BUILD_VARIANT),full)
  full:=1
else
  full:=0
endif

MAKE_VARS = \
	EXTRA_CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
	LDFLAGS="$(TARGET_LDFLAGS)"

MAKE_FLAGS += \
	CC="$(TARGET_CC)" \
	OUTPUT="$(PKG_BUILD_DIR)/" \
	prefix="/usr" \
	$(if $(findstring c,$(OPENWRT_VERBOSE)),V=1,V='') \
	check_feat=0 \
	feature-clang-bpf-co-re=0 \
	feature-libbfd=$(full) \
	feature-llvm=0 \
	feature-libcap=0 \
	feature-disassembler-four-args=1 \
	feature-disassembler-init-styled=1

MAKE_PATH = src

define Package/mimic-bpftool-$(BUILD_VARIANT)/install
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/bpftool \
		$(1)/usr/libexec/bpftool-$(BUILD_VARIANT)
endef

HOST_MAKE_FLAGS += \
	-C src \
	CC="$(HOSTCC)"
	OUTPUT="$(HOST_BUILD_DIR)/" \
	prefix="/usr" \
	$(if $(findstring c,$(OPENWRT_VERBOSE)),V=1,V='') \
	check_feat=0 \
	feature-clang-bpf-co-re=0 \
	feature-libbfd=1 \
	feature-llvm=0 \
	feature-libcap=0 \
	feature-disassembler-four-args=1 \
	feature-disassembler-init-styled=1

define Host/Install
	$(INSTALL_DIR) $(STAGING_DIR_HOST)/usr/sbin
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/src/bpftool \
		$(STAGING_DIR_HOST)/usr/sbin/mimic-bpftool
endef

$(eval $(call BuildPackage,mimic-bpftool-full))
$(eval $(call BuildPackage,mimic-bpftool-minimal))
$(eval $(call HostBuild))
