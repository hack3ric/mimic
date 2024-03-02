#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "mimic.h"

struct mimic_whitelist_map mimic_whitelist SEC(".maps");
struct mimic_conns_map mimic_conns SEC(".maps");

char _license[] SEC("license") = "GPL";
