#!/usr/bin/env bats

setup() {
  [ "$UID" -eq 0 ] || skip
  ns="Mstartup-$BATS_TEST_NUMBER-$$"
  ip netns add "$ns"
  ip -n "$ns" link add mstart0 type dummy
  ip -n "$ns" link set mstart0 up
  memcheck=()
  if command -v valgrind >/dev/null; then
    memcheck=(valgrind --leak-check=full --errors-for-leak-kinds=all --error-exitcode=99
      --suppressions="$BATS_TEST_DIRNAME/data/libbpf.supp")
  fi
}

teardown() {
  if [ -n "${ns:-}" ]; then ip netns del "$ns"; fi
}

@test "epoll setup failure releases BPF attachments and allocations" {
  run ip netns exec "$ns" "${memcheck[@]}" "$BATS_TEST_DIRNAME/../out/test-epoll-failure" \
    run mstart0 -Leth -xskb
  [ "$status" -eq 24 ] # EMFILE, rather than Valgrind's error exit code
  [[ "$output" == *"failed to create epoll"* ]]
  ip -n "$ns" -details -json link show dev mstart0 | jq -e '.[0].xdp == null'
}
