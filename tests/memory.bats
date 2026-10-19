#!/usr/bin/env bats

@test "memory allocation and cleanup" {
  local memcheck=()
  if command -v valgrind >/dev/null; then
    memcheck=(valgrind --leak-check=full --errors-for-leak-kinds=all --error-exitcode=1)
  fi
  "${memcheck[@]}" "$BATS_TEST_DIRNAME/../out/test-memory"
}

@test "BPF packet buffer ownership and TCP option parsing" {
  [ "$UID" -eq 0 ] || skip
  "$BATS_TEST_DIRNAME/../out/test-pktbuf-bpf"
}
