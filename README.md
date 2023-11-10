# Mimic

Mimic is a UDP to TCP obfuscator designed to bypass UDP QoS and port blocking. Based on eBPF, it directly mangles data inside Traffic Control (TC) subsystem in the kernel space, achieving remarkably high performance compared to other projects, such as [udp2raw](https://github.com/wangyu-/udp2raw) or [Phantun](https://github.com/dndx/phantun).

## Usage

The following requirements need to be satisfied on every machine that would run Mimic:

- Recent Linux kernel: version >= 5.15 should work
- libbpf, version 1.x: `apt install libbpf1` or similar, depending on your Linux distro

Deploying Mimic does not require changing much of your existing configuration, as it directly interacts with packets in their ingress and egress paths. You can keep the same IP and port number of the UDP sockets at both ends, and just need to make sure the binding network interface and filters are set up correctly.

A filter is an entry of whitelist that looks like a key-value pair: `{origin}={ip}:{port}`. Origin is either `local` or `remote`, indicating which side's IP and port is matched. For example, `remote=192.0.2.1:6000` matches the server's IP (192.0.2.1) and its listening port (6000).

For IPv6, the IP field needs to be surrounded by square brackets: `local=[fc00::cafe]:7000`. This means packets originated from or sending to the local machine using that IP and port is processed. Multiple parallel filters can be specified by passing multiple `-f` options.

The general usage of Mimic CLI looks like:

```console
$ mimic -i <interface> -f <filter1> [-f <filter2> [...]]
```

## Example

Assume that you have a server with an IP of 192.0.2.253. It hosts an UDP service on 7777. The server's main interface (the one that this connection goes through) is `eth0`, while the client's is `enp1s0`.

On server side, specify that all packets in and out `eth0` with that server's IP and port is processed:

```console
$ mimic -i eth0 -f local=192.0.2.253:7777
```

On client side, `remote` filter is used to specify the server address:

```console
$ mimic -i enp1s0 -f remote=192.0.2.253:7777
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

## Benchmark

TODO

## License

The project is licensed under GNU General Public License version 2 (GPLv2). See LICENSE for more details.
