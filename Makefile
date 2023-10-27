CC := clang
CFLAGS := -mcpu=v3 -O2
DEBUG ?= 1
OUTFILE ?= mimic.o

ifneq ($(DEBUG),)
CFLAGS += -g -D__DEBUG__
endif

all: build

build:
	$(CC) --target=bpf $(CFLAGS) -c src/bpf/main.c -o $(OUTFILE)

clean:
	rm -f mimic.o

IF ?= virbr0

manual-test-start:
	@if [ `id -u` -ne 0 ]; then                                     \
		echo "You must run manual-test-start with root priviledges."; \
		exit 1;                                                       \
	fi
	@make build
	tc qdisc add dev $(IF) clsact
	tc filter add dev $(IF) egress prio 1 handle 1 bpf da obj $(OUTFILE) sec egress
	tc filter add dev $(IF) ingress prio 1 handle 1 bpf da obj $(OUTFILE) sec ingress

manual-test-stop:
	@if [ `id -u` -ne 0 ]; then                                    \
		echo "You must run manual-test-stop with root priviledges."; \
		exit 1;                                                      \
	fi
	@make clean
	tc qdisc del dev $(IF) clsact
