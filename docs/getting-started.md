# Getting Started

## Platform Support

To run Mimic, you need a fairly recent Linux kernel (>= 6.1, due to usage of [dynptrs](https://lwn.net/Articles/910873/)), compiled with basic BPF support. For more detail, see [checksum hacks](checksum-hacks#platform-support).

You will not need to worry too much about it; most desktop and server Linux distros enable these configurations by default and should work out of the box.

OpenWrt support is on the way, though one might need to build the entire image; see [here](openwrt.md).

## Running Mimic

Deploying Mimic does not require changing much of your existing configuration, as it directly interacts with packets in their ingress and egress paths, acting as a transparent overlay. You can keep the same IP and port number of the UDP sockets at both ends, and just need to make sure the binding network interface and filters are set up correctly.

### Systemd

Mimic ships systemd service in distro packages. It takes care of a lot of things such as loading [kernel module](#kernel-module) and running Mimic as a service.

To use it, first create a configuration for an interface at `/etc/mimic/<interface>.conf`. See [`/usr/share/doc/mimic/eth0.conf.example`](../install/eth0.conf) for example configuration.

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

```console
# insmod out/mimic.ko
```

### Command Usage

The general command of running a Mimic instance looks like:

```console
# mimic run -f <filter1> [-f <filter2> [...]] <interface>
```

See [mimic(1)](mimic.1.md) for more information on command-line options and detailed configuration.

## Firewall

Mimic not only mangles packets from UDP to TCP transparently using eBPF, but also sends out control packets e.g. SYN and keepalive, using Linux's raw(7) socket. As TC eBPF happens after netfilter's output hook, and XDP before input hook, the former is recognized as UDP by netfilter. However, the latter is still regarded as TCP (as it really is). To make firewall work with Mimic, one should treat Mimic's traffic as *both TCP and UDP*.

## Notes on XDP Native Mode

Some network drivers, like Intel's e1000, igb, igc and Nvidia (Mellanox)'s mlx4, mlx5 have XDP offload function, running XDP programs in their drivers (native mode) in contrast to running in the Linux kernel (skb mode). However, one may exhibit unstable traffic when using Mimic on such drivers (especially Intel ones). I encountered several times on my router with Intel i225 NIC (igc driver), but none on another one using Realtek R8111 (r8169 driver), which does not support native mode and always falls back to skb mode. If you encounter sudden traffic loss, you may want to specify `xdp_mode = skb` in your configuration file, or pass `--xdp-mode skb` as arguments when running Mimic.

XDP can also directly run on NIC hardware (hardware mode), but only a handful of SmartNICs support it. I don't have them so I can't test them.
