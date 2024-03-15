BPF_CC ?= clang
BPFTOOL ?= /usr/sbin/bpftool

# -g is required (by Clang) to generate BTF
# for bpf-gcc, use -gbtf and -mco-re
BPF_CFLAGS ?= --target=bpf -mcpu=v3 -g -O3
MODE ?= debug

ifeq ($(MODE), debug)
CFLAGS ?= -O0
CFLAGS += -g
else ifeq ($(MODE), release)
CFLAGS ?= -O2
endif

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

MIMIC_SHARED_HEADERS := $(wildcard src/shared/*.h)

MIMIC_BPF_SRCS := $(wildcard src/bpf/*.c)
MIMIC_BPF_OBJS := $(MIMIC_BPF_SRCS:.c=.o)
MIMIC_BPF_HEADERS := src/bpf/vmlinux.h $(wildcard src/bpf/*.h) $(MIMIC_SHARED_HEADERS)

MIMIC_SRCS := $(wildcard src/*.c)
MIMIC_OBJS := $(MIMIC_SRCS:.c=.o)
MIMIC_HEADERS := src/bpf_skel.h $(wildcard src/*.h) $(MIMIC_SHARED_HEADERS)
MIMIC_LINK_LIBS := -lbpf -ljson-c
ifneq ($(ARGP_STANDALONE),)
MIMIC_LINK_LIBS += -largp
endif

.PHONY: build build-cli build-kmod generate generate-skel generate-vmlinux generate-pot clean .FORCE
.FORCE:

all: build
build: build-cli build-kmod
build-cli: out/mimic
build-kmod: out/mimic.ko
generate: generate-skel generate-vmlinux
generate-skel: src/bpf_skel.h
generate-vmlinux: src/bpf/vmlinux.h
generate-pot: out/mimic.pot

MKDIR_P = mkdir -p $(@D)

src/bpf/vmlinux.h:
	$(BPFTOOL) btf dump file $(KERNEL_VMLINUX) format c > $@

$(filter src/bpf/%.o, $(MIMIC_BPF_OBJS)): src/bpf/%.o: src/bpf/%.c $(MIMIC_BPF_HEADERS)
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
	$(MAKE) -C src/kmod
	cp src/kmod/mimic.ko $@

out/mimic.pot:
	$(MKDIR_P)
	find src -type f -regex '.*\.[ch]' | xargs xgettext -k_ -kN_ -o $@ --

clean:
	$(MAKE) -C src/kmod $@
	rm -rf out/
	find . -type f -name *.o -delete
	rm -f src/bpf_skel.h
	rm -f src/bpf/vmlinux.h
