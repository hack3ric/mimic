CC = clang
BPF_CFLAGS ?= -O2
CFLAGS ?= -O2
DEBUG ?= 1

ifneq ($(DEBUG),)
BPF_CFLAGS += -D__DEBUG__
CFLAGS += -g -D__DEBUG__
endif

all: build
build: out/mimic
generate: src/bpf/skel.h

out/:
	mkdir $@

# -g is required in order to obtain BTF
out/mimic.bpf.o: out/
	$(CC) --target=bpf -g -mcpu=v3 $(BPF_CFLAGS) -c src/bpf/main.c -o $@

src/bpf/skel.h: out/mimic.bpf.o
	bpftool gen skeleton out/mimic.bpf.o > $@

out/mimic: src/bpf/skel.h
	$(CC) $(CFLAGS) src/main.c -o $@ -lbpf

clean:
	rm -rf out/
	rm -f src/bpf/skel.h
