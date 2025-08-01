# Checksum Hacks

The Linux kernel comes with support to [*checksum offload*](https://www.kernel.org/doc/html/v6.12/networking/checksum-offloads.html), which leaves calculations of [RFC 1071](https://datatracker.ietf.org/doc/html/rfc1071) checksum in TCP, UDP and more (and also CRC for SCTP) to the NIC if possible, reducing CPU usage. This is done using three fields inside [`struct sk_buff`](https://github.com/torvalds/linux/blob/b86545e02e8c22fb89218f29d381fa8e8b91d815/include/linux/skbuff.h#L867):

- `ip_summed`, if set to `CSUM_PARTIAL`, will make the `skb` do the offloading;
- `csum_start` points to the start of the L4 packet to be summed; and
- `csum_offset` points to the 16-bit checksum field where it should be written.

(Encapsulations, as well as RX checksum offload are not discussed here for the sake of simplicity. We only focus on TX checksum offload.)

This leaves us a problem: when Mimic transforms a UDP packet to fake TCP one, `csum_start` and `csum_offset` cannot be changed in eBPF alone; there is simply no such methods of doing that. This will make the NIC (or whatever that finishes the checksum) put the checksum in the wrong place and makes the packet malformed.

To solve this issue, we have to extend eBPF on the kernel side, and we also have to maintain compatibility across kernel versions. Mimic implements two kinds of **checksum hacks** implemented in its kernel module:

- `kfunc` (default): using [BPF kernel functions](https://www.kernel.org/doc/html/v6.12/bpf/kfuncs.html) to extend eBPF. This is the current way of extending eBPF in-tree, and requires BPF JIT (`CONFIG_BPF_JIT=y`) and BTF (`CONFIG_DEBUG_INFO_BTF=y`) support. `CONFIG_NET_SCH_INGRESS=m` and `CONFIG_DEBUG_INFO_BTF_MODULES=y` may also be needed.

- `kprobe`: change existing BPF helpers' behaviour using kprobe. This is way hackier, but could be used when kernel BTF is not present (with BPF program's own BTF information also stripped). It also allows the kernel module to be optional, since [not every case requires checksum hack](#when-is-checksum-hack-not-necessary). Pass `CHECKSUM_HACK=kprobe` to `make` to enable this behaviour (you would almost certainly need `STRIP_BTF_EXT=1` too).

Normally with most Linux distros (Debian, Fedora, Arch, etc.), `kfunc` should be used. But in restricted environments like OpenWrt, `kprobe` might be the option.

## When is Checksum Hack Not Necessary?

When the two conditions below both matches, checksum hack is not necessary.

1. Driver does not use `csum_offset`, or checksum offload is maunally disabled.

    You can check if your NIC's driver source code contains `csum_offset` by simple searching either inside Linux kernel source code or out-of-tree somewhere. Realtek and Mediatek's Ethernet driver does not use it, while Intel and many others uses it.

2. UDP socket in userspace.

    Kernel `udptunnel{4,6}`, used by many in-kernel tunnels such as [WireGuard](https://www.wireguard.com/), and encapsulation protocols like [FOU](https://www.man7.org/linux/man-pages/man8/ip-fou.8.html) and [GENEVE](https://github.com/torvalds/linux/blob/master/drivers/net/geneve.c), is always `CSUM_PARTIAL` (see [udp4](https://github.com/torvalds/linux/blob/b86545e02e8c22fb89218f29d381fa8e8b91d815/net/ipv4/udp.c#L1041) and [udp6](https://github.com/torvalds/linux/blob/b86545e02e8c22fb89218f29d381fa8e8b91d815/net/ipv6/ip6_checksum.c#L115)). Userspace implementations are not affected, like [wireguard-go](https://git.zx2c4.com/wireguard-go), [OpenVPN](https://openvpn.net/) and [Hysteria](https://hysteria.network/). (However, since Hysteria uses (modified) QUIC, it is sometimes better to keep it as-is than using Mimic or other fake TCP solutions and turning it to something unknown to the middleboxes.)

## Platform Support

`kfunc` hack requires `CONFIG_BPF_JIT=y` and `CONFIG_DEBUG_INFO_BTF=y` to be set. Below lists kernel support for BPF JIT and kfunc call per CPU architecture:

- x86_64, aarch64: >= v6.1
- riscv64: [>= v6.4](https://github.com/torvalds/linux/commit/d40c3847b485acc3522b62b020f77dcd38ca357f)
- i386: JIT will fail with `** NOT YET **: opcode 85` in kernel output
  - This means [eBPF on i386 does not implement BPF_PSEUDO_CALL](https://github.com/torvalds/linux/blob/786c8248dbd33a5a7a07f7c6e55a7bfc68d2ca48/arch/x86/net/bpf_jit_comp32.c#L2092)
- 32-bit arm: Does not support kfunc call
  - There are [patches](https://lwn.net/ml/linux-kernel/20221126094530.226629-1-yangjihong1@huawei.com/) to implement this, but not merged

`kprobe` hack requires `CONFIG_KRETPROBE=1`, and any Linux version >= 6.1 will work.
