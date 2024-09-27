#!/usr/bin/env bats

BATS_TEST_RETRIES=2
BATS_NO_PARALLELIZE_WITHIN_FILE=true

: "${SLEEP_MULTIPLIER:=1}"
if [ "$SLEEP_MULTIPLIER" -lt 1 ]; then
  >&2 echo SLEEP_MULTIPLIER cannot be less than 1
  exit 1
fi

load util

TEST_NETWORK_ID="Mconntr"
load env/router

pcap_file=("$BATS_RUN_TMPDIR"/conntrack-{1..2}.pcapng)
pcap_file_dest=("$BATS_TEST_DIRNAME"/../out/conntrack-{1..2}.pcapng)
fifo=("$BATS_RUN_TMPDIR/"conntrack-{1..2}.pipe)
output=("$BATS_RUN_TMPDIR/"conntrack-{1..2}.output)
fifo_pid=()
socat_pid=()
mimic_pid=()

setup_file() {
  [ "$UID" -eq 0 ] || skip
  router_env_setup

  sleep $((2 * SLEEP_MULTIPLIER))

  for _i in {0..1}; do
    tshark -i ${br[$_i]} -w ${pcap_file[$_i]} &
  done
}

teardown_file() {
  router_env_cleanup
  for _i in {0..1}; do
    cp "${pcap_file[$_i]}" "${pcap_file_dest[$_i]}"
    chmod +r "${pcap_file_dest[$_i]}"
  done
}

setup() {
  _setup
}

teardown() {
  _teardown
}

_test_random_traffic_one_sided() {
  setup_mimic_socat "$1"
  for _i in {0..499}; do
    head -c $((SRANDOM % 1400)) /dev/urandom >>${fifo[$2]}
    sleep $(echo "0.001 * $SLEEP_MULTIPLIER * ($RANDOM % 10)" | bc -l)
  done
  check_mimic_is_alive
}

@test "try to drain peer window using one-sided traffic (IPv4)" {
  _test_random_traffic_one_sided v4 $((RANDOM % 2))
}

@test "try to drain peer window using one-sided traffic (IPv6)" {
  _test_random_traffic_one_sided v6 $((RANDOM % 2))
}

@test "check if TCP connections are contiguous" {
  for _file in "${pcap_file[@]}"; do
    [ "$(tshark -r "$_file" -T json -Y tcp.flags.reset==1 | jq length)" -le 4 ]
  done
}
