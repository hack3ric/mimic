#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "egress.h"
#include "ingress.h"

char _license[] SEC("license") = "GPL";
