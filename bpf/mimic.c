#include "vmlinux.h"  // IWYU pragma: keep

#include <bpf/bpf_helpers.h>

#include "mimic.h"

int log_verbosity = 0;

struct mimic_whitelist_map mimic_whitelist SEC(".maps");
struct mimic_conns_map mimic_conns SEC(".maps");
struct mimic_rb_map mimic_rb SEC(".maps");

#ifndef _MIMIC_BPF_INLINE_ALL_FUNCS
#include "mimic-impl.h"  // IWYU pragma: export
#endif

char _license[] SEC("license") = "GPL";
