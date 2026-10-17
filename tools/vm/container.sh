#!/usr/bin/env bash
# Internal build commands. /src is read-only; /work and /output belong to the caller.
set -euo pipefail

case "$1" in
cli)
  workspace=$2
  variant=$3
  compiler=$4
  jobs=$5

  cd "$workspace"

  flags=()
  case "$variant" in
  compat-6.1) flags+=(COMPAT_LINUX_6_1=1) ;;
  compat-6.6) flags+=(COMPAT_LINUX_6_6=1) ;;
  generic) ;;
  *) exit 2 ;;
  esac

  name="mimic-$variant-clang-$compiler"
  make -j"$jobs" build-cli BPF_CC="clang-$compiler" BPFTOOL=bpftool \
    USE_LIBXDP=1 CHECKSUM_HACK=kfunc "${flags[@]}"

  mkdir -p /output/vm-binaries
  cp out/mimic "/output/vm-binaries/$name"
  cp out/mimic.bpf.o "/output/vm-binaries/$name.bpf.o"
  "llvm-objdump-$compiler" -S out/mimic.bpf.o > "/output/vm-binaries/$name.dis"

  {
    "clang-$compiler" --version
    gcc --version
    bpftool version
    pkg-config --modversion libbpf libffi libxdp
    printf 'variant=%s\n' "$variant"
  } > "/output/vm-binaries/$name.build.txt"
  ;;
kernel)
  entry=$2
  kernel=$3
  revision=$4
  repository=$5
  metadata=$6
  jobs=$7

  # An incomplete build is never treated as a cache hit.
  rm -rf "$entry"
  mkdir -p "$entry/tree" "$entry/lvh/kernels"

  git -C "$entry/tree" init
  git -C "$entry/tree" fetch --depth=1 "$repository" "$revision"
  git -C "$entry/tree" checkout --detach FETCH_HEAD
  test "$(git -C "$entry/tree" rev-parse HEAD)" = "$revision"

  jq --arg kernel "$kernel" --arg jobs "-j$jobs" \
    '.kernels |= map(select(.name == $kernel) | .extra_make_args = [.extra_make_args[]?, $jobs])' \
    "$metadata" > "$entry/lvh/kernels.json"
  ln -s "$entry/tree" "$entry/lvh/kernels/$kernel"

  lvh kernels --dir "$entry/lvh" build "$kernel"
  make -C "$entry/tree/tools/bpf/resolve_btfids" -j"$jobs"

  cp "$entry/tree"/tar-install/boot/vmlinuz-* "$entry/vmlinuz"
  cp -a "$entry/tree/tar-install/lib/modules" "$entry/modules"

  # These links refer to build paths, not files needed by the guest.
  rm -f "$entry"/modules/*/build "$entry"/modules/*/source

  make -s -C "$entry/tree" kernelrelease > "$entry/release"
  cp "$entry/tree/.config" "$entry/config"

  # Keep the prepared tree and BTF for external modules, without duplicate packages/objects.
  rm -rf "$entry/tree/tar-install" "$entry/lvh"
  find "$entry/tree" -type f \( -name '*.o' -o -name '*.tar' \) -delete
  touch "$entry/ready"
  ;;
module)
  workspace=$2
  entry=$3
  destination=$4
  jobs=$5

  make -C "$workspace/kmod" -j"$jobs" SYSTEM_BUILD_DIR="$entry/tree" CHECKSUM_HACK=kfunc
  cp "$workspace/kmod/mimic.ko" "$destination"
  ;;
*)
  echo "Unknown container command: $1" >&2
  exit 2
  ;;
esac
