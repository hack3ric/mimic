# Getting Started

## Platform Support

To run Mimic, you need a fairly recent Linux kernel (>= 6.1, due to usage of [dynptrs](https://lwn.net/Articles/910873/)), compiled with basic BPF support. For more detail, see [checksum hacks](checksum-hacks#platform-support).

You will not need to worry too much about it; most desktop and server Linux distros enable these configurations by default and should work out of the box.

OpenWrt support is on the way, though one might need to build the entire image; see [here](openwrt.md).

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

```console
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
