# Building from Source

## Dependencies

- **Linux kernel**: [as mentioned in Getting Started](getting-started.md#kernel-support), along with its headers: `` apt install linux-{image,headers}-$(uname -r) `` on Debian or similar
- **GNU make**
- **Clang**: version >= 15
- **GCC** (if kernel is built using it)
- **pahole, bpftool**: for generating BPF stuff
- **libbpf 1.x**: `apt install libbpf-dev` on Debian or similar
- **libffi**: `apt install libffi-dev` on Debian or similar
- **argp-standalone** (if not glibc)

## Building

Just simply run `make` to compile:

```console
$ make  # or...
$ make build  # or...
$ make build-cli build-tools build-kmod
```

To build statically linked CLI and tools, specify `STATIC=1`.

Additionally, [checksum hacks](checksum-hacks.md) can be specified:

```console
$ make CHECKSUM_HACK=kfunc  # This is the default
$ make CHECKSUM_HACK=kprobe
$ make CHECKSUM_HACK=kprobe STRIP_BTF_EXT=1
```

## Building Distro Packages

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
Debian 12 and Ubuntu before 24.10 need to enable Backports repository for the build dependency `dh-sequence-dlopenlibdeps`.

## Notes on Building Kernel Module

*TODO: multiple options for vmlinux and resolve_btfids workaround*

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
