# Mimic

[Getting Started](docs/getting-started.md) | [mimic(1)](docs/mimic.1.md)

Mimic is a UDP to TCP obfuscator designed to bypass UDP QoS and port blocking. Based on eBPF, it directly mangles data inside Traffic Control (TC) subsystem in the kernel space and restores data using XDP, achieving remarkably high performance compared to other projects, such as [udp2raw](https://github.com/wangyu-/udp2raw) or [Phantun](https://github.com/dndx/phantun).

## Installation

Mimic currently ships prebuilt packages for Debian 12 (bookworm) and Ubuntu 24.04 (noble) for x86_64 in [GitHub releases](https://github.com/hack3ric/mimic/releases). Release artifacts contains:

- **`<codename>_mimic_<ver>_<arch>.deb`: Mimic CLI**
- **`<codename>_mimic-dkms_<ver>_<arch>.deb`: Mimic kernel module for DKMS**
- `<codename>_mimic{,-dkms}_dbgsym_<ver>_<arch>.{,d}deb`: Debug symbols
- `*.sha256`: SHA256 checksum of the corresponding file

To install, download both `mimic` and `mimic-dkms` packages (the first two of the above) *prefixed with the correct distribution codename* and install with:

```console
# apt install ./*_mimic_*.deb ./*_mimic-dkms_*.deb
```

OpenWrt support is currently experimental and waiting for 24.10 release, see [`openwrt` branch](https://github.com/hack3ric/mimic/tree/openwrt) and [OpenWrt Support](docs/openwrt.md) documentation.

For building from source (including AUR and other Debian and Ubuntu versions), see [Building from Source](docs/building.md) for more information.

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
- Two VMs running Debian 12 on libvirt QEMU/KVM, with 4 vcores each, using emulated e1000e NIC
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
