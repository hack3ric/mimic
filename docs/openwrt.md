# OpenWrt Support

We are trying to bring Mimic to OpenWrt. The packaging effort is going on in the [`openwrt` branch](https://github.com/hack3ric/mimic/tree/openwrt). However, OpenWrt does not come with both kernel BTF and kprobe configuration enabled, and [checksum hacks](checksum-hacks.md) cannot be applied without recompiling the kernel.

As some of the scenarios [does not require checksum hack](checksum-hacks.md#when-is-checksum-hack-not-necessary), we build Mimic on OpenWrt with `CHECKSUM_HACK=kprobe`. You can use Mimic normally without the kernel module, but if you do need the checksum hacks, you have to build the OpenWrt image manually.

*TODO: image build tutorial*
