ARG LVH_VERSION=v0.0.30
FROM quay.io/lvh-images/lvh:${LVH_VERSION} AS lvh
FROM docker.io/library/ubuntu:24.04

ARG BPFTOOL_VERSION=v7.7.0
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg && \
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | \
      gpg --dearmor -o /usr/share/keyrings/llvm.gpg && \
    for version in 17 18 19 20 21; do \
      echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] https://apt.llvm.org/noble/ llvm-toolchain-noble-$version main" \
        >> /etc/apt/sources.list.d/llvm.list; \
    done && \
    apt-get update && apt-get install -y --no-install-recommends \
      autoconf bc bison build-essential cpio flex gawk git jq kmod \
      libbpf-dev libelf-dev libffi-dev libiberty-dev libncurses-dev \
      libpci-dev libssl-dev libudev-dev libxdp-dev lz4 pahole pkg-config \
      python3 rsync xz-utils zstd \
      clang-16 clang-17 clang-18 clang-19 clang-20 clang-21 \
      llvm-16 llvm-17 llvm-18 llvm-19 llvm-20 llvm-21 && \
    rm -rf /var/lib/apt/lists/*
RUN cd /tmp && \
    archive="bpftool-${BPFTOOL_VERSION}-amd64.tar.gz" && \
    base="https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}" && \
    curl -fL --retry 3 -O "${base}/${archive}" -O "${base}/${archive}.sha256sum" && \
    sha256sum --check "${archive}.sha256sum" && \
    tar -xzf "$archive" && install -m 0755 bpftool /usr/local/bin/bpftool && \
    rm -f bpftool "$archive" "${archive}.sha256sum"
COPY --from=lvh /usr/bin/lvh /usr/local/bin/lvh
RUN apt-get update && apt-get install -y --no-install-recommends \
      qemu-system-x86 qemu-utils && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /work
