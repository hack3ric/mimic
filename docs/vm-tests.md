# VM compatibility tests

`tools/test-vm` builds Mimic and the kernel in a container, then runs
`mimic run lo --check` in an LVH/QEMU guest. CI uses the same runner.
For traffic tests, see [Tests & Benchmark](building.md#tests--benchmark).

## Setup

Use Linux amd64 with Docker or `podman-docker`, Bash, coreutils, and read/write
access to `/dev/kvm`. Install the remaining host tools:

```console
# Debian/Ubuntu
sudo apt-get install qemu-system-x86 qemu-utils openssh-client curl git jq rsync util-linux iproute2
# Arch Linux
sudo pacman -S qemu-system-x86 qemu-img openssh curl git jq rsync util-linux iproute2
```

For rootless Podman, enable its [Docker-compatible API](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html)
so LVH can download images:

```bash
systemctl --user start podman.socket
export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
```

Install the pinned LVH version from the repository root:

```bash
source tools/vm/defaults.sh
lvh_container_id=$(docker create "quay.io/lvh-images/lvh:$LVH_VERSION")
lvh_install_dir=$(mktemp -d)
docker cp "$lvh_container_id:/usr/bin/lvh" "$lvh_install_dir/lvh"
sudo install -m 0755 "$lvh_install_dir/lvh" /usr/local/bin/lvh
docker rm "$lvh_container_id"
rm -rf "$lvh_install_dir"
```

## Run

Run from the repository root as your regular user, with container and KVM access:

```bash
tools/test-vm run --kernel 6.12 --clang 19
tools/test-vm run --kernel 6.1 --clang 19 --jobs 1 --mem 1024M
tools/test-vm run --kernel 6.6 --clang 18,20 --keep-vm
```

Kernels: `6.1`, `6.6`, `6.12`, `6.18`, `bpf-next`. Clang: `16` through `21`.
The runner selects compatibility flags for 6.1 and 6.6 automatically. Local runs
allow combinations excluded from CI.

Builds include uncommitted changes. The first run downloads images and builds a
kernel; later runs reuse `.cache/vm/`. Use `--kernel-revision <full-commit-SHA>`
to pin a kernel; otherwise the runner follows its configured branch.

Defaults: `--jobs 2`, `--cpus 2`, `--mem 4G`, `--ssh-port 2222` (localhost only).
Use another port while a retained VM is running. See `tools/test-vm --help` for
all options.

## Results and debugging

Logs and per-binary exit codes are in `out/vm/<run-id>/`; build logs are in
`out/vm-build/`. The runner checks every selected binary and returns nonzero if
any check fails.

The VM stops on exit or interruption. `--keep-vm` keeps it after checks, even if
they fail, and prints an SSH command. Stop it with:

```bash
tools/test-vm stop <run-id>
```

This removes the VM's disk overlay and keeps its logs. Keep the cached root
image until the VM has stopped.

## Separate builds and CI artifacts

```bash
tools/test-vm build --clang 19,20 --variant generic,compat-6.6
tools/test-vm prepare --kernel 6.6
tools/test-vm run --kernel 6.6 --binaries-dir out/vm-binaries
```

Each build replaces `out/vm-binaries/` with executables, BPF objects, disassembly,
and build metadata. Pass downloaded CI executables with `--binaries-dir` to use
them instead of rebuilding Mimic.

`build --ci-matrix` builds the CI combinations. `prepare --resolve-only` prints
kernel revisions and cache metadata as JSON. See [the workflow](../.github/workflows/test-lvh.yml)
for the current matrix and exclusions.
