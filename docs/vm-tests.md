# VM compatibility tests

`tools/test-vm` builds Mimic and the kernel, then launches LVH/QEMU in a
container. The guest runs `mimic run lo --check`. CI uses the same runner.
For traffic tests, see [Tests & Benchmark](building.md#tests--benchmark).

## Setup

Use Linux amd64 with Docker or `podman-docker`, Bash, coreutils, and read/write
access to `/dev/kvm`. Install the remaining host tools:

```console
# Debian/Ubuntu
sudo apt-get install openssh-client curl git jq rsync util-linux iproute2
# Arch Linux
sudo pacman -S openssh curl git jq rsync util-linux iproute2
```

LVH and QEMU are included in the container image. Rootless Podman also needs
crun to preserve KVM group access. If Podman uses another runtime, set this in
`~/.config/containers/containers.conf`:

```toml
[engine]
runtime = "crun"
```

## Run

Run from the repository root as your regular user, with container and KVM access:

```bash
tools/test-vm run --kernel 6.12 --clang 19
tools/test-vm run --kernel 6.1 --clang 19 --jobs 1 --mem 1024M
tools/test-vm run --kernel 6.6 --clang 18,20 --keep-vm
```

Kernels: `6.1`, `6.6`, `6.12`, `6.18`, `bpf-next`. Clang: `16` through `21`.
Builds are shared across kernels.

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

This removes the container and disk overlay, keeping the logs. Keep the cached root
image until the VM has stopped.

## Separate builds and CI artifacts

```bash
tools/test-vm build --clang 19,20
tools/test-vm prepare --kernel 6.6
tools/test-vm run --kernel 6.6 --binaries-dir out/vm-binaries
```

Each build replaces `out/vm-binaries/` with executables, BPF objects, disassembly,
and build metadata. Pass downloaded CI executables with `--binaries-dir` to use
them instead of rebuilding Mimic.

`build --ci-matrix` builds once with each of the six Clang versions.
`prepare --resolve-only` prints kernel revisions and cache metadata as JSON.
The [CI workflow](../.github/workflows/test-lvh.yml) checks Linux 6.1, 6.6, 6.12,
and 6.18 with Clang 16–21. The bpf-next kernel remains disabled in CI.
