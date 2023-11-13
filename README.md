# Mimic

Mimic is an experimental UDP to TCP obfuscator designed to bypass UDP QoS and port blocking. Based on eBPF, it directly mangles data inside Traffic Control (TC) subsystem in the kernel space and restores data using XDP, achieving remarkably high performance compared to other projects, such as [udp2raw](https://github.com/wangyu-/udp2raw) or [Phantun](https://github.com/dndx/phantun).

**Note:** The project is still in early development stage. Use with care and try at your own risk.

## Usage

The following requirements need to be satisfied on every machine that would run Mimic:

- Recent Linux kernel: version >= 5.15 should work
- libbpf, version 1.x: `apt install libbpf1` or similar, depending on your Linux distro

Deploying Mimic does not require changing much of your existing configuration, as it directly interacts with packets in their ingress and egress paths. You can keep the same IP and port number of the UDP sockets at both ends, and just need to make sure the binding network interface and filters are set up correctly.

A filter is an entry of whitelist that looks like a key-value pair: `{origin}={ip}:{port}`. Origin is either `local` or `remote`, indicating which side's IP and port is matched. For example, `remote=192.0.2.1:6000` matches the server's IP (192.0.2.1) and its listening port (6000).

For IPv6, the IP field needs to be surrounded by square brackets: `local=[2001:db8::cafe]:7000`. This means packets originated from or sending to the local machine using that IP and port is processed. Multiple parallel filters can be specified by passing multiple `-f` options.

The general usage of Mimic CLI looks like:

```console
$ mimic -f <filter1> [-f <filter2> [...]] <interface>
```

## Examples

Assume that you have a server with an IP of 192.0.2.253. It hosts an UDP service on 7777. The server's main interface (the one that this connection goes through) is `eth0`, while the client's is `enp1s0`.

On server side, specify that all packets in and out `eth0` with that server's IP and port is processed:

```console
$ mimic -f local=192.0.2.253:7777 eth0
```

On client side, `remote` filter is used to specify the server address:

```console
$ mimic -f remote=192.0.2.253:7777 enp1s0
```

## Building from Source

The following dependencies is required:

- GNU make
- libbpf 1.x and its header files: `apt install libbpf-dev` or similar
- Clang, version >= 14

Then just simply:

```console
$ make
```

To build without debug information:

```console
$ make DEBUG=
```

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

## Caveats

#### Currently only Ethernet packets are correctly parsed.

Support for other L2 protocols such as PPP(oE) and WLAN will be added.

#### Sequence number syncing will fail when connecting two virtual machines on the same virtual network bridge, both with virtio-net NIC.

It seems the virtio driver/implementation still considers fake TCP segment as UDP, and overwrites the "UDP checksum" field (which is now the lower 16 bits of the sequence number). This will not affect most scenarios since the VMs are on a virtualized network bridge. If you are experimenting, just switch the NIC on one of the VMs to an emulated one, like Intel 82574 (e1000e) on libvirt.

## Future work

- More obfuscation options: XOR, padding, etc.
- Make fake TCP optional
- Variable cwnd
- State reset mechanism

## License

The project is licensed under GNU General Public License version 2 (GPLv2). See LICENSE for more details.
