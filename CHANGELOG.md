# Changelog for Mimic

## 0.6.1 (2024-11-23)

- Debian packaging fixes regarding DKMS

## 0.6.0 (2024-11-02)

- Do not depend on bpf_xdp_get_buff_len for payload length; this could be larger than the actual packet length, and the real length should be retrieved from packet headers
- Add kprobe checksum hacks, along with previous kfunc implementation
- Enable XDP fragments support
- RST is now sent to peers when Mimic is shutting down
- Allow domain names in filters; they are only resolved when Mimic starts, and only resolved IPs are stored
- Allow fixed or pseudo-random padding in packets

## 0.5.0 (2024-08-05)

- Track TCP window size and send window change packets to prevent conntrack failure
- (distro packages) Tries to extract vmlinux from boot image if vmlinux is not available in module build directory
- Add passive mode, i.e. "do not initiate handshake", enabled by setting handshake interval to 0

## 0.4.2 (2024-05-24)

- Fix systemd service file, adding missing \[Install\] section
- Fix version display in Mimic CLI

## 0.4.1 (2024-05-24)

- Fix configuration file parsing
- Make trace output more visible on certain terminals

## 0.4.0 (2024-05-24)

- Variable congestion window to better mimic real TCP
- Notify supervisor when Mimic is ready (currently only systemd)
- Drop json-c dependency, lock file now uses key=value pair
- Add handshake and keepalive mechanism, as well as its settings, both global and filter-specific
- Add mimic(1) manpage
- Better logging UX, including full TCP traffic trace

## 0.3.1 (2024-04-21)

- Ubuntu: prebuilt distribution switched from 23.10 (mantic) to 24.04 LTS (noble)
- Add null checks in `pktbuf.c` to prevent edge-case segfaults
- Reduce error message on failing to send buffered packets
- Fix compiler warnings

## 0.3.0 (2024-04-07)

- Proper TCP handshake by actively sending packets using raw socket (see [README#Caveats](https://github.com/hack3ric/mimic/tree/v0.3.0?tab=readme-ov-file#caveats) for more information)
- Only calculate checksum deltas on ingress path
- Correctly build and install DKMS kernel modules on Debian and Ubuntu

## 0.2.1 (2024-03-19)

- Packaging fixes & documentation

## 0.2.0 (2024-03-18)

- Added lock files for each interface
- Added `mimic show`, allowing viewing information of a running Mimic instance
- Better logging UX
- Added reading configuration from file
- Systemd service
- ...and more internal changes

## 0.1.1 (2024-03-02)

- Fix `open with O_CREAT in second argument needs 3 arguments`
- debian: split into mimic and mimic-dkms
- debian: fix Ubuntu build

## 0.1.0 (2024-02-29)

- Initial release
