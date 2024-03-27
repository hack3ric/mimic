#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "mimic.h"

struct mimic_whitelist_map mimic_whitelist SEC(".maps");
struct mimic_conns_map mimic_conns SEC(".maps");
struct mimic_settings_map mimic_settings SEC(".maps");
struct mimic_send_rb_map mimic_send_rb SEC(".maps");

char _license[] SEC("license") = "GPL";
