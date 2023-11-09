CC := clang
CFLAGS := -mcpu=v3 -O2 $(EXTRA_CFLAGS)
DEBUG ?= 1

ifneq ($(DEBUG),)
CFLAGS += -g -D__DEBUG__
endif

all: build
build: out/mimic
generate: src/bpf/skel.h

out/:
	mkdir $@

# -g is required in order to obtain BTF
out/mimic.bpf.o: out/
	$(CC) --target=bpf -g $(CFLAGS) -c src/bpf/main.c -o $@

src/bpf/skel.h: out/mimic.bpf.o
	bpftool gen skeleton out/mimic.bpf.o > $@

out/mimic: src/bpf/skel.h
	$(CC) $(CFLAGS) src/main.c -o $@ -lbpf

clean:
	rm -rf out/
	rm -f src/bpf/skel.h
