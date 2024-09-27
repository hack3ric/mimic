#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "../csum-hack.h"
#include "common.h"
#include "csum-hack.h"

__bpf_kfunc_start_defs();

// Inspect kernel representation of a BPF `__sk_buff`.
//
// Newer versions of Linux has `bpf_cast_to_kern_ctx` kfunc. This function is meant to provide such
// functionality for lower versions of kernel.
__bpf_kfunc struct sk_buff* mimic_inspect_skb(struct __sk_buff* skb_bpf) {
  return (struct sk_buff*)skb_bpf;
}

// Change checksum position in `sk_buff` to instruct hardware/driver/kernel to offset checksum
// correctly.
__bpf_kfunc int mimic_change_csum_offset(struct __sk_buff* skb_bpf, __u16 new_proto) {
  return change_csum_offset((struct sk_buff*)skb_bpf, new_proto);
}

__bpf_kfunc_end_defs();
