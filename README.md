# Mimic

Mimic is an experimental UDP to TCP obfuscator designed to bypass UDP QoS and port blocking. Based on eBPF, it directly mangles data inside Traffic Control (TC) subsystem in the kernel space and restores data using XDP, achieving remarkably high performance compared to other projects, such as [udp2raw](https://github.com/wangyu-/udp2raw) or [Phantun](https://github.com/dndx/phantun).

## Preparation

Mimic currently ships prebuilt packages for Debian 12 and Ubuntu 24.04 for x86_64 in [GitHub releases](https://github.com/hack3ric/mimic/releases). Download both `mimic` and `mimic-dkms` packages suffixed with the correct distribution and install with:

```console
# apt install ./mimic_*.deb ./mimic-dkms_*.deb
```

For building from source (including AUR and other Debian and Ubuntu versions), see [Building from Source](#building-from-source) for more information.

You may want to use systemd to manage your Mimic instances. See [Usage for Systemd](#usage-for-systemd) for more information.

### Kernel Support

To run Mimic, you need a fairly recent Linux kernel (>= 6.1, due to usage of [dynptrs](https://lwn.net/Articles/910873/)), compiled with BPF (`CONFIG_BPF_SYSCALL=y`), BPF JIT (`CONFIG_BPF_JIT=y`), and BTF (`CONFIG_DEBUG_INFO_BTF=y`) support. Most distros enable them on 64-bit systems by default. On single-board computers with custom kernel, recompilation with these options enabled is probably needed.

To check if current kernel have these options enabled, run `` grep CONFIG_[...] /boot/config-`uname -r` `` or `zgrep CONFIG_[...] /proc/config.gz`, where `CONFIG_[...]` is one of the kernel configurations above.

BPF support varies depending on architecture, kernel version and distro configurations. Be ready if installed kernel won't load eBPF programs JITed even when enabled, or JIT does not support calling kernel function.

The following is a list of kernel versions verified to work on certain architectures, or reasons why it will not work; feel free to test out and contribute to the list!

- x86_64, aarch64: >= v6.1
- riscv64: >= v6.7
- i386: JIT will fail with `** NOT YET **: opcode 85` in kernel output

### Kernel Module

*If you are using systemd, skip this part as the systemd service already takes care of loading Mimic kernel module.*

Otherwise, first load the kernel module which provides lower-level access of network packages for eBPF programs. If you use packaged version of Mimic, DKMS should compile it against current kernel automatically:

```console
# modprobe mimic
```

Optionally, load Mimic kernel module at startup:

```console
# echo 'mimic' > /etc/modules-load.d/mimic.conf
```

Otherwise, refer to [Building from Source](#building-from-source) to build and load kernel packages manually:

```console
$ make out/mimic.ko
$ sudo insmod out/mimic.ko
```

## Usage

Deploying Mimic does not require changing much of your existing configuration, as it directly interacts with packets in their ingress and egress paths, acting as a transparent overlay. You can keep the same IP and port number of the UDP sockets at both ends, and just need to make sure the binding network interface and filters are set up correctly.

A filter is an entry of whitelist that looks like a key-value pair: `{origin}={ip}:{port}`. Origin is either `local` or `remote`, indicating which side's IP and port is matched. For example, `remote=192.0.2.1:6000` matches the server's IP (192.0.2.1) and its listening port (6000).

For IPv6, the IP field needs to be surrounded by square brackets: `local=[2001:db8::cafe]:7000`. This means packets originated from or sending to the local machine using that IP and port is processed. Multiple parallel filters can be specified in configuration files as `filter={origin}={ip}:{port}`, or by passing multiple `-f` options.

The general command of running a Mimic instance looks like:

```console
# mimic run -f <filter1> [-f <filter2> [...]] <interface>
```

See [mimic(1)](docs/mimic.1.md) for more information on command-line options and detailed configuration.

### Examples

Assume that you have a server with an IP of 192.0.2.253. It hosts an UDP service on 7777. The server's main interface (the one that this connection goes through) is `eth0`, while the client's is `enp1s0`. Root permission is *required* in order to load BPF programs.

On server side, specify that all packets in and out `eth0` with that server's IP and port is processed:

```console
# mimic run -f local=192.0.2.253:7777 eth0
```

On client side, `remote` filter is used to specify the server address:

```console
# mimic run -f remote=192.0.2.253:7777 enp1s0
```

### Usage for Systemd

Mimic ships systemd service in distro packages. To use it, first create a configuration for an interface at `/etc/mimic/<interface>.conf`. See `/etc/mimic/eth0.conf.example` for example configuration.

Then simply start the per-interface service:

``` console
# systemctl start mimic@<interface>
```

### Notes on Firewall

Due to its transparent nature (i.e. UDP applications can work seamlessly with or without Mimic running), Mimic plays nice with existing firewall rules too.

However, do note that since both TC happens after netfilter's output hook, and XDP before input hook, one should treat traffic through Mimic as UDP. TCP rules have no effect on Mimic's fake TCP traffic.

## Building from Source

Arch Linux users can use `mimic-bpf` or `mimic-bpf-git` packages in AUR:

```console
$ git clone https://aur.archlinux.org/mimic-bpf.git  # or mimic-bpf-git.git
$ cd mimic-bpf*
$ makepkg -si
```

Debian (>= 12, bookworm or later) and Ubuntu (>= 23.04, lunar or later) users can directly build Mimic as .deb package, with DKMS support:

```console
$ sudo apt build-dep .
$ debuild -b -us -uc
```

Then install with:

```console
# apt install ../mimic_*.deb ../mimic-dkms_*.deb
```

Debian < 12 (bullseye, buster or earlier) and Ubuntu < 23.04 (kinetic, jammy or earlier) are not supported due to outdated libbpf 0.x and Linux kernel < 6.1.

Otherwise, the following dependencies is required:

- Linux kernel, [as previously mentioned](#kernel-support), along with its headers: `` apt install linux-{image,headers}-`uname -r` `` on Debian or similar
- GNU make
- Clang version >= 14, and optionally GCC (if system kernel is built using it)
- pahole, bpftool (for generating BPF stuff)
- libbpf 1.x: `apt install libbpf-dev` on Debian or similar
- libffi: `apt install libffi-dev` on Debian or similar

`bpf-gcc` could be used, but commit [6103df1e](https://github.com/gcc-mirror/gcc/commit/6103df1e4fae5192c507484b1d32f00c42c70b54) needs to be included/backported; see Makefile for details. Note that although it did compile, it probably wouldn't pass the verifier.

Then just simply run `make` to generate dynamically linked CLI and kernel modules. To build statically linked CLI, use `make STATIC=1`.

On Alpine and possibly other non-glibc distros, `argp-standalone` is needed. Install it, and use `make ARGP_STANDALONE=1` to link against it.

### Notes on Building Kernel Module

If the following output appears:
```
  ...
  LD [M]  /path/to/mimic.ko
  BTF [M] /path/to/mimic.ko
Skipping BTF generation for /path/to/mimic.ko due to unavailability of vmlinux
```

Just copy current vmlinux to kernel module build directory:

```console
# cp /sys/kernel/btf/vmlinux /lib/modules/`uname -r`/build
```

Furthermore, the following error will occur on Debian, or sometimes other distros:

```
/bin/sh: 1: ./tools/bpf/resolve_btfids/resolve_btfids: not found
```

This is because they forget to ship this Linux kernel building utility (see [bug report](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1027304) for Debian). To solve this, `resolve_btfids` has to be built from Linux source (preferrably the same version as the current kernel) and placed in that location:

```console
$ tar xf /path/to/linux-source-*.tar.*
$ make -C linux-source-*/tools/bpf/resolve_btfids
$ sudo install -D linux-source-*/tools/bpf/resolve_btfids/resolve_btfids /lib/modules/`uname -r`/build/tools/bpf/resolve_btfids/resolve_btfids
```

The Debian packages already worked around these issues; see debian/ directory for more details.

## Tests & Benchmark

Mimic uses [network namespaces](https://www.man7.org/linux/man-pages/man7/network_namespaces.7.html) for test environments, [bats](https://github.com/bats-core/bats-core) for integration tests, and [iperf3](https://github.com/esnet/iperf) for benchmark.

To run tests or benchmark, first install test dependencies:

```
# apt install bats bc ethtool iperf3 jq socat tshark wireguard-tools
```

Then simply:

```
# make test
# make bench
```

If you want to pass extra arguments to test frameworks, use:

```
# bats tests/ <extra args for bats>
# tests/bench.bash [clean|veth|wg|mimic] <extra args for iperf3>
```

First argument of `tests/bench.bash` allows users to also benchmark against virtual ETH interface and raw WireGuard. `mimic` (default if not specified) benchmarks against WireGuard through Mimic.

## Details

Mimic extends every UDP packet with 12 bytes. First 12 bytes of the data is moved to the back, and the UDP header is transformed into TCP header in place.

When used with a tunnel protocol, make sure to lower the MTU bytes by 12. For example, a WireGuard tunnel over IPv6 and Ethernet would need to change its MTU from 1420 to 1408. For IPv4, the default value of 1420 will work, with the maximum MTU being 1428.

The following shows how Mimic works visually:

```
+---------------+-------------------------+---------+----------------------------------------+
| Ethernet (14) |    IPv4 Header (20)     | UDP (8) |               Data  ...                |
+---------------+-------------------------+---------+----------------------------------------+
                                                    |<------------->|
                                                     Part to be moved                             ...here
                                                                                             |<-------------->|
+---------------+-------------------------+-------------------------+------------------------+----------------+
| Ethernet (14) |    IPv4 Header (20)     |     TCP Header (20)     |   Remaining Data  ...  |  Fragment (12) |
+---------------+-------------------------+-------------------------+------------------------+----------------+
```

## Benchmark

*TODO: to be re-tested*

### Environment

- Host CPU Core i9-13900F, running Arch Linux (2023-11-13)
- Two VMs running Debian 12 on libvirt QEMU/KVM, with 4 vcores each, using emulated e1000e NIC ([see below](#sequence-number-syncing-will-fail-when-connecting-two-virtual-machines-on-the-same-virtual-network-bridge-both-with-virtio-net-nic))
- Test commands: `iperf3 -s` and `iperf3 -c <server IPv4> -t 20`
- WireGuard tunnels run over IPv4

### Speed

| Connection                                           | MTU  | Recv Speed | Send CPU Usage | Recv CPU Usage |
| ---------------------------------------------------- | ---- | ---------- | -------------- | -------------- |
| **Direct**                                           | 1500 | 5.28 Gbps  | 4x10%          | 2x100%, 2x1%   |
| **WireGuard**                                        | 1440 | 2.38 Gbps  | 1x100%, 3x10%  | 1x40%, 3x35%   |
| **WireGuard + udp2raw**<br>w/ fake TCP + `--fix-gro` | 1342 | 788 Mbps   | 1x100%, 3x10%  | 1x100%, 3x20%  |
| **WireGuard + Phantun**                              | 1428 | 980 Mbps   | 4x30%          | 4x35%          |
| **WireGuard + Mimic**                                | 1428 | 2.23 Gbps  | 1x100%, 3x10%  | 1x40%, 3x35%   |

### CPU usage

`iperf3 -c <server IPv4> -t 20 -b 500M`

| Connection                                           | MTU  | Recv Speed | Send CPU Usage | Recv CPU Usage |
| ---------------------------------------------------- | ---- | ---------- | -------------- | -------------- |
| **Direct**                                           | 1500 | 500 Mbps   | 4x<5%          | 4x<5%          |
| **WireGuard**                                        | 1440 | 500 Mbps   | 1x35%, 4x<5%   | 4x<5%          |
| **WireGuard + udp2raw**<br>w/ fake TCP + `--fix-gro` | 1342 | 500 Mbps   | 1x50%, 3x25%   | 1x55%, 3x10%   |
| **WireGuard + Phantun**                              | 1428 | 500 Mbps   | 4x15%          | 4x20%          |
| **WireGuard + Mimic**                                | 1428 | 500 Mbps   | 1x38%, 4x<5%   | 4x<5%          |

## License

The project is licensed under GNU General Public License version 2 only (GPL-2.0-only). See LICENSE for more details.
