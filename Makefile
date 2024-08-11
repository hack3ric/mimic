mimic_common_headers := $(wildcard common/*.h)

mimic_bpf_src := $(wildcard bpf/*.c)
mimic_bpf_obj := $(mimic_bpf_src:.c=.o)
mimic_bpf_headers := bpf/vmlinux.h $(wildcard bpf/*.h) $(mimic_common_headers)

mimic_src := $(wildcard src/*.c)
mimic_obj := $(mimic_src:.c=.o)
mimic_headers := src/bpf_skel.h $(wildcard src/*.h) $(mimic_common_headers)
mimic_link_libs := -lbpf -lffi

mimic_tools := $(patsubst tools/%.c,%,$(wildcard tools/*.c))

# Compile options

BPF_CC ?= clang
BPFTOOL ?= /usr/sbin/bpftool
LLVM_STRIP ?= llvm-strip

# -g is required (by Clang) to generate BTF
# for bpf-gcc, use -mcpu=v3 -gbtf -mco-re -O2
BPF_TARGET ?= bpf
BPF_CFLAGS += --target=$(BPF_TARGET) -mcpu=v3 -g -O2

BPF_CFLAGS += -iquote. -Wall -std=gnu99
CFLAGS += -iquote. -Wall -std=gnu99

# Specify compiler option presets
MODE ?=
ifeq ($(MODE), debug)
CFLAGS += -O0 -g
else ifeq ($(MODE), release)
CFLAGS += -O2
endif

# Whether to use argp-standalone
#
# If host glibc is detected, the option is automatically enabled. This
# behaviour can be overriden.
ifeq ($(ARGP_STANDALONE),)
ifeq ($(filter "gnu libc" "glibc" "free software foundation",$(shell ldd --version 2>&1 | tr '[A-Z]' '[a-z]')),)
ARGP_STANDALONE := 1
endif
endif
ifeq ($(ARGP_STANDALONE),1)
mimic_link_libs += -largp
endif

# Whether to link CLI statically
ifneq ($(STATIC),)
mimic_link_libs += -lelf -lzstd -lz
LDFLAGS += -static
endif

# Specify path of vmlinux for generating bpf/vmlinux/system.h
ifeq ($(KERNEL_VMLINUX),)
ifeq ($(KERNEL_UNAME),)
KERNEL_VMLINUX := /sys/kernel/btf/vmlinux
else ifeq ($(KERNEL_UNAME),$(shell uname -r))
KERNEL_VMLINUX := /sys/kernel/btf/vmlinux
else ifneq ($(wildcard /usr/lib/debug/lib/modules/$(KERNEL_UNAME)/vmlinux),)
KERNEL_VMLINUX := /usr/lib/debug/lib/modules/$(KERNEL_UNAME)/vmlinux
else ifneq ($(wildcard /lib/modules/$(KERNEL_UNAME)/build/vmlinux),)
KERNEL_VMLINUX := /lib/modules/$(KERNEL_UNAME)/build/vmlinux
endif  # KERNEL_UNAME
endif  # KERNEL_VMLINUX

# Specify whether to use system vmlinux
ifneq ($(BPF_USE_SYSTEM_VMLINUX),)
BPF_CFLAGS += -D_MIMIC_BPF_USE_SYSTEM_VMLINUX
use_system_vmlinux_req := bpf/vmlinux/system.h
else
BPF_CFLAGS += -D_MIMIC_BPF_TARGET_ARCH_$(shell $(CC) -dumpmachine | sed 's/-.*//')
endif  # BPF_USE_SYSTEM_VMLINUX

# Mimic runtime directory, where the lock files are stored
RUNTIME_DIR ?= /run/mimic
CFLAGS += -DMIMIC_RUNTIME_DIR="\"$(RUNTIME_DIR)\""

# Select packet checksum hack method
#
# When transport header changes from UDP to TCP in TC, skb->csum_offset still
# points to UDP's checksum position. Some network drivers may use the value to
# do checksum offload, causing packet corruption. This field is not accesible
# through BPF's `struct __sk_buff`, so we have to use kernel module to hack
# into `struct sk_buff`.
#
# Selecting kfunc requires CONFIG_DEBUG_INFO_BTF=y, and running the compiled
# Mimic requires loading the corresponding kernel module.
#
# Using kprobe requires CONFIG_KRETPROBES=y and CONFIG_KALLSYMS=y, and making
# the kernel module optional. The hack simply goes out of effect if the module
# is not loaded.
CHECKSUM_HACK ?= kfunc
ifeq ($(filter kfunc kprobe,$(CHECKSUM_HACK)),)
$(error unknown checksum hack '$(CHECKSUM_HACK)')
endif
BPF_CFLAGS += -DMIMIC_CHECKSUM_HACK_$(CHECKSUM_HACK)
CFLAGS += -DMIMIC_CHECKSUM_HACK_$(CHECKSUM_HACK)

# Whether to strip .BTF.ext section from BPF object
#
# Removing the section removes dependency on kernel BTF and improves
# compatibility, but also makes the program lose CO-RE functionality.
STRIP_BTF_EXT ?=

# Enable BPF dynamic pointer usage (requires Linux >= 6.1)
#
# This is used in caching outgoing packets while attempting handshake, and
# re-send them afterwards. It is a quality-of-life feature, but not necessary.
ENABLE_BPF_DYNPTR ?= 1
ifeq ($(ENABLE_BPF_DYNPTR),1)
BPF_CFLAGS += -DMIMIC_ENABLE_BPF_DYNPTR
endif

# Enable XDP fragment support (requires Linux >= 5.18?)
ENABLE_XDP_FRAGS ?= 1
ifeq ($(ENABLE_XDP_FRAGS),1)
BPF_CFLAGS += -DMIMIC_ENABLE_XDP_FRAGS
endif

# Rules

mkdir_p = mkdir -p $(@D)
check_options := out/.options.$(shell echo $(BPF_CC) $(CC) $(BPFTOOL) $(BPF_CFLAGS) $(CFLAGS) | sha256sum | awk '{ print $$1 }')

.PHONY: .FORCE
.FORCE:

all: build

.PHONY: build build-cli build-kmod build-tools
build: build-cli build-kmod build-tools
build-cli: out/mimic
build-kmod: out/mimic.ko
build-tools: $(patsubst %,out/%,$(mimic_tools))

.PHONY: generate-skel generate-manpage generate-pot generate-compile-commands
generate-skel: src/bpf_skel.h
generate-manpage: out/mimic.1.gz
generate-pot: out/mimic.pot
generate-compile-commands: compile_commands.json

.PHONY: generate-dkms generate-akms
generate-dkms:
	$(MAKE) -C kmod dkms.conf
generate-akms:
	$(MAKE) -C kmod AKMBUILD

.PHONY: test
test: build-cli
	bats tests

.PHONY: bench
bench: build-cli
	tests/bench.bash

.PHONY: clean
clean:
	$(MAKE) -C kmod $@
	rm -rf out/
	find . -type f -name *.o -delete
	rm -f src/bpf_skel.h
	rm -f bpf/vmlinux/system.h

out/.options.%:
	$(mkdir_p)
	rm -f out/.options.*
	touch $@

bpf/vmlinux/system.h:
ifneq ($(KERNEL_VMLINUX),)
	$(BPFTOOL) btf dump file $(KERNEL_VMLINUX) format c > $@
else
	@echo vmlinux file not found and KERNEL_VMLINUX not specified >2
	@exit 1
endif

$(mimic_bpf_obj): bpf/%.o: bpf/%.c $(mimic_bpf_headers) $(use_system_vmlinux_req) $(check_options)
	$(BPF_CC) $(BPF_CFLAGS) -D_MIMIC_BPF -c -o $@ $<

out/mimic.bpf.o: $(mimic_bpf_obj)
	$(mkdir_p)
	$(BPFTOOL) gen object $@ $(mimic_bpf_obj)
ifneq ($(STRIP_BTF_EXT),)
	$(LLVM_STRIP) --remove-section=.BTF.ext --no-strip-all $@
endif

src/bpf_skel.h: out/mimic.bpf.o
	$(BPFTOOL) gen skeleton out/mimic.bpf.o > $@

$(filter src/%.o, $(mimic_obj)): src/%.o: $(mimic_headers) $(check_options)

out/mimic: $(mimic_obj)
	$(mkdir_p)
	$(CC) $(CFLAGS) $(mimic_obj) -o $@ $(LDFLAGS) $(mimic_link_libs)

out/mimic.ko: .FORCE build-tools
	$(mkdir_p)
	$(MAKE) -C kmod
	cp kmod/mimic.ko $@

define generate_tool_rule
out/$(1): tools/$(1).c $(mimic_common_headers) $(check_options)
	$$(mkdir_p)
	$(CC) $(CFLAGS) $$< -o $$@ $(LDFLAGS)
endef
$(foreach _tool,$(mimic_tools),$(eval $(call generate_tool_rule,$(_tool))))

out/mimic.1.gz: docs/mimic.1.md
	$(mkdir_p)
	ronn -r --pipe $< | gzip -c > $@

out/mimic.pot:
	$(mkdir_p)
	find src -type f -regex '.*\.[ch]' | xargs xgettext -k_ -kN_ -o $@ --

compile_commands.json: clean
	bear -- $(MAKE)
