# Changelog for Mimic

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
