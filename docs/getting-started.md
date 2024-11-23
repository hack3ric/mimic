# Getting Started

## Kernel Support

To run Mimic, you need a fairly recent Linux kernel (>= 6.1, due to usage of [dynptrs](https://lwn.net/Articles/910873/)), compiled with BPF (`CONFIG_BPF_SYSCALL=y`), BPF JIT (`CONFIG_BPF_JIT=y`), and BTF (`CONFIG_DEBUG_INFO_BTF=y`) support. Most distros enable them on 64-bit systems by default. On single-board computers with custom kernel, recompilation with these options enabled is probably needed.

To check if current kernel have these options enabled, run `` grep CONFIG_[...] /boot/config-`uname -r` `` or `zgrep CONFIG_[...] /proc/config.gz`, where `CONFIG_[...]` is one of the kernel configurations above.

BPF support varies depending on architecture, kernel version and distro configurations. Be ready if installed kernel won't load eBPF programs JITed even when enabled, or JIT does not support calling kernel function.

### Platform Support

- x86_64, aarch64: >= v6.1
- riscv64: [>= v6.4](https://github.com/torvalds/linux/commit/d40c3847b485acc3522b62b020f77dcd38ca357f)
- i386: JIT will fail with `** NOT YET **: opcode 85` in kernel output
  - This means [eBPF on i386 does not implement BPF_PSEUDO_CALL](https://github.com/torvalds/linux/blob/786c8248dbd33a5a7a07f7c6e55a7bfc68d2ca48/arch/x86/net/bpf_jit_comp32.c#L2092)
- arm: Does not support kfunc call
  - There are [patches](https://lwn.net/ml/linux-kernel/20221126094530.226629-1-yangjihong1@huawei.com/) to implement this, but not merged

## Running Mimic

Deploying Mimic does not require changing much of your existing configuration, as it directly interacts with packets in their ingress and egress paths, acting as a transparent overlay. You can keep the same IP and port number of the UDP sockets at both ends, and just need to make sure the binding network interface and filters are set up correctly.

### Systemd

Mimic ships systemd service in distro packages. It takes care of a lot of things such as loading [kernel module](#kernel-module) and running Mimic as a service.

To use it, first create a configuration for an interface at `/etc/mimic/<interface>.conf`. See [`/usr/share/doc/mimic/eth0.conf.example`](eth0.conf.example) for example configuration.

Then simply start the per-interface service, `eth0` in the following example:

``` console
# systemctl start mimic@eth0
```

### Kernel Module

*If you plan to use the [systemd service](#systemd), skip these steps.*

Mimic's kernel module provides lower-level access of network packets for eBPF programs. If you use packaged version of Mimic, DKMS should compile it against current kernel automatically:

```console
# modprobe mimic
```

Optionally, load Mimic kernel module at startup:

```console
# echo 'mimic' > /etc/modules-load.d/mimic.conf
```

If you are building from source, load the compiled kernel module manually:

```
# insmod out/mimic.ko
```

### Command Usage

The general command of running a Mimic instance looks like:

```console
# mimic run -f <filter1> [-f <filter2> [...]] <interface>
```

See [mimic(1)](mimic.1.md) for more information on command-line options and detailed configuration.

## Notes on Firewall

Due to its transparent nature (i.e. UDP applications can work seamlessly with or without Mimic running), Mimic plays nice with existing firewall rules too.

However, do note that since both TC happens after netfilter's output hook, and XDP before input hook, one should *treat traffic through Mimic as UDP instead of TCP*. TCP rules have no effect on Mimic's fake TCP traffic.

