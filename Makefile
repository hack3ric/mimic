BPF_CC ?= clang
CC ?= clang
BPFTOOL ?= /usr/sbin/bpftool

# -g is required (by Clang) to generate BTF
# for bpf-gcc, use -gbtf and -mco-re
BPF_CFLAGS ?= --target=bpf -mcpu=v3 -g -O3
CFLAGS ?= -O2

MIMIC_BPF_OBJS := src/bpf/mimic.o
MIMIC_BPF_HEADERS := src/bpf/vmlinux.h \
	$(wildcard src/bpf/*.h) \
	$(wildcard src/shared/*.h)

MIMIC_OBJS := src/mimic.o
MIMIC_HEADERS := src/bpf_skel.h \
	$(wildcard src/*.h) \
	$(wildcard src/shared/*.h)

.PHONY: build build-cli build-kmod generate generate-skel generate-vmlinux clean .FORCE
.FORCE:

all: build
build: build-cli build-kmod
build-cli: out/mimic
build-kmod: out/mimic.ko
generate: generate-skel generate-vmlinux
generate-skel: src/bpf_skel.h
generate-vmlinux: src/bpf/vmlinux.h

MKDIR_P = mkdir -p $(@D)

src/bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(MIMIC_BPF_OBJS): $(MIMIC_BPF_OBJS:.o=.c) $(MIMIC_BPF_HEADERS)
	$(BPF_CC) $(BPF_CFLAGS) -c -o $@ $<

out/mimic.bpf.o: $(MIMIC_BPF_OBJS)
	$(MKDIR_P)
	$(BPFTOOL) gen object $@ $(MIMIC_BPF_OBJS)

src/bpf_skel.h: out/mimic.bpf.o
	$(BPFTOOL) gen skeleton out/mimic.bpf.o > $@

$(MIMIC_OBJS): $(MIMIC_HEADERS)

out/mimic: $(MIMIC_OBJS)
	$(MKDIR_P)
	$(CC) $(CFLAGS) $(MIMIC_OBJS) -o $@ $(LDFLAGS) -lbpf

out/mimic.ko: .FORCE
	$(MKDIR_P)
	$(MAKE) -C src/kmod
	cp src/kmod/mimic.ko $@

clean:
	$(MAKE) -C src/kmod $@
	rm -rf out/
	find . -type f -name *.o -delete
	rm -f src/bpf_skel.h
