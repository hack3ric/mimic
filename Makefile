BPF_CC ?= clang
BPFTOOL ?= /usr/sbin/bpftool

# -g is required (by Clang) to generate BTF
# for bpf-gcc, use -mcpu=v3 -gbtf -mco-re -O2
BPF_CFLAGS ?= --target=bpf -mcpu=v3 -g -O2
MODE ?= debug

ifeq ($(MODE), debug)
CFLAGS ?= -O0
CFLAGS += -g
else ifeq ($(MODE), release)
CFLAGS ?= -O2
endif

BPF_CFLAGS += -Wall -std=gnu99
CFLAGS += -Wall -std=gnu99

ifeq ($(KERNEL_UNAME),)
KERNEL_VMLINUX := /sys/kernel/btf/vmlinux
else ifeq ($(KERNEL_UNAME),$(shell uname -r))
KERNEL_VMLINUX := /sys/kernel/btf/vmlinux
else ifneq ($(wildcard /usr/lib/debug/lib/modules/$(KERNEL_UNAME)/vmlinux),)
KERNEL_VMLINUX := /usr/lib/debug/lib/modules/$(KERNEL_UNAME)/vmlinux
else ifneq ($(wildcard /lib/modules/$(KERNEL_UNAME)/build/vmlinux),)
KERNEL_VMLINUX := /lib/modules/$(KERNEL_UNAME)/build/vmlinux
else
$(error vmlinux file not found)
endif

MIMIC_COMMON_HEADERS := $(wildcard common/*.h)

MIMIC_BPF_SRCS := $(wildcard bpf/*.c)
MIMIC_BPF_OBJS := $(MIMIC_BPF_SRCS:.c=.o)
MIMIC_BPF_HEADERS := bpf/vmlinux.h $(wildcard bpf/*.h) $(MIMIC_COMMON_HEADERS)

MIMIC_SRCS := $(wildcard src/*.c)
MIMIC_OBJS := $(MIMIC_SRCS:.c=.o)
MIMIC_HEADERS := src/bpf_skel.h $(wildcard src/*.h) $(MIMIC_COMMON_HEADERS)
MIMIC_LINK_LIBS := -lbpf -lffi
ifneq ($(ARGP_STANDALONE),)
MIMIC_LINK_LIBS += -largp
endif
ifneq ($(STATIC),)
MIMIC_LINK_LIBS += -lelf -lzstd -lz
LDFLAGS += -static
endif

RUNTIME_DIR ?=
ifneq ($(RUNTIME_DIR),)
CFLAGS += -DMIMIC_RUNTIME_DIR="\"$(RUNTIME_DIR)\""
endif

.PHONY: build build-cli build-kmod generate generate-skel generate-vmlinux generate-manpage generate-pot test bench clean .FORCE
.FORCE:

all: build
build: build-cli build-kmod
build-cli: out/mimic
build-kmod: out/mimic.ko
generate: generate-skel generate-vmlinux
generate-skel: src/bpf_skel.h
generate-vmlinux: bpf/vmlinux.h
generate-manpage: out/mimic.1.gz
generate-pot: out/mimic.pot

MKDIR_P = mkdir -p $(@D)

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file $(KERNEL_VMLINUX) format c > $@

$(filter bpf/%.o, $(MIMIC_BPF_OBJS)): bpf/%.o: bpf/%.c $(MIMIC_BPF_HEADERS)
	$(BPF_CC) $(BPF_CFLAGS) -D_MIMIC_BPF -c -o $@ $<

out/mimic.bpf.o: $(MIMIC_BPF_OBJS)
	$(MKDIR_P)
	$(BPFTOOL) gen object $@ $(MIMIC_BPF_OBJS)

src/bpf_skel.h: out/mimic.bpf.o
	$(BPFTOOL) gen skeleton out/mimic.bpf.o > $@

$(filter src/%.o, $(MIMIC_OBJS)): src/%.o: $(MIMIC_HEADERS)

out/mimic: $(MIMIC_OBJS)
	$(MKDIR_P)
	$(CC) $(CFLAGS) $(MIMIC_OBJS) -o $@ $(LDFLAGS) $(MIMIC_LINK_LIBS)

out/mimic.ko: .FORCE
	$(MKDIR_P)
	$(MAKE) -C kmod
	cp kmod/mimic.ko $@

out/mimic.1.gz: docs/mimic.1.md
	$(MKDIR_P)
	pandoc -s -t man $< | gzip -c > $@

out/mimic.pot:
	$(MKDIR_P)
	find src -type f -regex '.*\.[ch]' | xargs xgettext -k_ -kN_ -o $@ --

test: build-cli
	bats tests

bench: build-cli
	tests/bench.bash

clean:
	$(MAKE) -C kmod $@
	rm -rf out/
	find . -type f -name *.o -delete
	rm -f src/bpf_skel.h
	rm -f bpf/vmlinux.h
