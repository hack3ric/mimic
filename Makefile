CC := clang
CFLAGS := -mcpu=v3 -O2 $(EXTRA_CFLAGS)
DEBUG ?= 1

ifneq ($(DEBUG),)
CFLAGS += -g -D__DEBUG__
endif

all: build

out/:
	mkdir $@

# -g is required in order to obtain BTF
out/mimic.o: out/
	$(CC) --target=bpf -g $(CFLAGS) -c src/bpf/main.c -o $@

src/mimic.skel.h: out/mimic.o
	bpftool gen skeleton out/mimic.o > $@

out/mimic: src/mimic.skel.h
	$(CC) $(CFLAGS) src/main.c -o $@ -lbpf

build: out/mimic

clean:
	rm -f mimic.o
	rm -f src/mimic.skel.h
