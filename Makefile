BPF_CC ?= clang --target=bpf
CC ?= clang
BPFTOOL ?= /usr/sbin/bpftool

BPF_CFLAGS ?= -O2
CFLAGS ?= -O2

.PHONY: build generate-skel generate-vmlinux clean .FORCE
.FORCE:

all: build
build: out/mimic out/mimic.ko
generate-skel: src/bpf/skel.h
generate-vmlinux: src/bpf/vmlinux.h

src/bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

out/:
	mkdir $@

# -g is required in order to obtain BTF
out/mimic.bpf.o: src/bpf/vmlinux.h out/
	$(BPF_CC) -g -mcpu=v3 $(BPF_CFLAGS) -c src/bpf/main.c -o $@

src/bpf/skel.h: out/mimic.bpf.o
	$(BPFTOOL) gen skeleton out/mimic.bpf.o > $@

out/mimic: src/bpf/skel.h
	$(CC) $(CFLAGS) src/main.c -o $@ -lbpf

out/mimic.ko: .FORCE
	$(MAKE) -C src/kmod
	cp src/kmod/mimic.ko $@

clean:
	rm -rf out/
	rm -f src/bpf/skel.h
#	rm -f src/bpf/vmlinux.h
	$(MAKE) -C src/kmod clean
