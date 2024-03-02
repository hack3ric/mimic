BPF_CC ?= clang
CC ?= clang
BPFTOOL ?= /usr/sbin/bpftool

BPF_CFLAGS ?= --target=bpf -mcpu=v3 -g -O3
CFLAGS ?= -O2

MIMIC_BPF_HEADERS := src/bpf/vmlinux.h \
	$(wildcard src/bpf/*.h) \
	$(wildcard src/shared/*.h)

MIMIC_OBJS := src/main.o
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

# -g is required in order to obtain BTF
out/mimic.bpf.o: src/bpf/main.c $(MIMIC_BPF_HEADERS)
	$(MKDIR_P)
	$(BPF_CC) $(BPF_CFLAGS) -c src/bpf/main.c -o $@

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
	$(MAKE) -C src/kmod clean
	rm -rf out/
	rm -f src/bpf_skel.h
	rm -f **/*.o
#	rm -f src/bpf/vmlinux.h
