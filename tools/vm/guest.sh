#!/usr/bin/env bash
# Arguments are paths relative to /host, not shell fragments.
set -euo pipefail

run_dir="/host/$1"
kernel_dir="/host/$2"
cd "$run_dir"

uname -a
test "$(uname -r)" = "$(cat "$kernel_dir/release")"

cp -a "$kernel_dir/modules/." /lib/modules/
depmod -a
modprobe sch_ingress
insmod mimic.ko
ip link set lo up

printf 'binary\texit_status\n' > results.tsv
failed=0

shopt -s nullglob
binaries=(bin/mimic-*)
if ((${#binaries[@]} == 0)); then
  echo 'No Mimic binaries selected' >&2
  exit 2
fi

for binary in "${binaries[@]}"; do
  name=${binary##*/}
  echo "Checking $name"

  status=0
  "$binary" run lo --check > "$name.stdout.log" 2> "$name.stderr.log" || status=$?

  cat "$name.stdout.log"
  cat "$name.stderr.log" >&2
  printf '%s\t%s\n' "$name" "$status" | tee -a results.tsv

  if ((status != 0)); then
    failed=1
  fi
done

exit "$failed"
