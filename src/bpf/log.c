#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "log.h"

struct mimic_log_rb_map mimic_log_rb SEC(".maps");

const volatile int log_verbosity = 0;
