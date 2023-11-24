CC = clang
BPF_CFLAGS ?= -O2
CFLAGS ?= -O2

all: build
build: out/mimic
generate: src/bpf/skel.h

src/bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

out/:
	mkdir $@

# -g is required in order to obtain BTF
out/mimic.bpf.o: src/bpf/vmlinux.h out/
	$(CC) --target=bpf -g -mcpu=v3 $(BPF_CFLAGS) -c src/bpf/main.c -o $@

src/bpf/skel.h: out/mimic.bpf.o
	bpftool gen skeleton out/mimic.bpf.o > $@

out/mimic: src/bpf/skel.h
	$(CC) $(CFLAGS) src/main.c -o $@ -lbpf

clean:
	rm -rf out/
	rm -f src/bpf/skel.h
	rm -f src/bpf/vmlinux.h
