#include <linux/kprobes.h>

#include "../impl.h"

extern struct kretprobe bpf_skb_change_type_probe, bpf_skb_change_proto_probe;

static struct kretprobe* mimic_probes[] = {
  &bpf_skb_change_type_probe,
  &bpf_skb_change_proto_probe,
};

int impl_init(void) { return register_kretprobes(mimic_probes, 2); }
void impl_exit(void) { unregister_kretprobes(mimic_probes, 2); }
