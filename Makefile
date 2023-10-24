all: build

build:
	clang --target=bpf -mcpu=v3 -O2 -g -c src/bpf/main.c -o mimic.o

clean:
	rm mimic.o
