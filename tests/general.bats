#!/usr/bin/env bats

BATS_TEST_RETRIES=2
BATS_NO_PARALLELIZE_WITHIN_FILE=true

: "${SLEEP_MULTIPLIER:=1}"
if [ "$SLEEP_MULTIPLIER" -lt 1 ]; then
  echo >&2 SLEEP_MULTIPLIER cannot be less than 1
  exit 1
fi

load util

TEST_NETWORK_ID="Mgeneral"
load env/switch

pcap_file="$BATS_RUN_TMPDIR/general.pcapng"
pcap_file_dest="$BATS_TEST_DIRNAME/../out/general.pcapng"
fifo=("$BATS_RUN_TMPDIR/"general-{1..2}.pipe)
output=("$BATS_RUN_TMPDIR/"general-{1..2}.output)
fifo_pid=()
socat_pid=()
mimic_pid=()

setup_file() {
  [ "$UID" -eq 0 ] || skip
  switch_env_setup --no-offload

  # Wait for netns to take effect, otherwise tests will probably hang
  sleep $((2 * SLEEP_MULTIPLIER))

  # Tshark will terminate itself when bridge is removed
  tshark -i $br -w "$pcap_file" &
}

teardown_file() {
  switch_env_cleanup
  cp "$pcap_file" "$pcap_file_dest"
  chmod +r "$pcap_file_dest"
}

setup() {
  _setup
}

teardown() {
  _teardown
}

_test_random_traffic() {
  setup_mimic_socat "$1"
  for _i in {0..499}; do
    head -c $((SRANDOM % 1400)) /dev/urandom >>${fifo[$((RANDOM % 2))]}
    sleep $(echo "0.001 * $SLEEP_MULTIPLIER * ($RANDOM % 10)" | bc -l)
  done
  check_mimic_is_alive
}

@test "test Mimic against some random UDP traffic (IPv4)" {
  _test_random_traffic v4
}

@test "test Mimic against some random UDP traffic (IPv6)" {
  _test_random_traffic v6
}

_test_packet_buffer() {
  setup_mimic_socat "$1"

  # Send multiple packets of random data in a short time (hopefully before
  # handshake)
  local random_data=()
  for _i in {0..5}; do
    random_data[$_i]="$(head -c $((SRANDOM % 1400)) /dev/urandom)"
    echo "${random_data[$_i]}" >>${fifo[0]}
  done

  # Wait for transmission
  sleep $((1 * SLEEP_MULTIPLIER))

  # Check if all sent data are present
  if [ "$(cat ${output[1]})" != "$(printf '%s\n' "${random_data[@]}")" ]; then
    >&2 echo "error: content mismatch"
    >&2 echo "  expected: $(echo "${random_data[@]}" | base64)"
    >&2 echo "  got: $(base64 "${output[1]}")"
    return 1
  fi
  check_mimic_is_alive
}

@test "test if packets before handshake is stored and re-sent afterwards (IPv4)" {
  _test_packet_buffer v4
}

@test "test if packets before handshake is stored and re-sent afterwards (IPv6)" {
  _test_packet_buffer v6
}

@test "test if there is no checksum error in packet capture" {
  local filter='
def csum_errors:
  .[]._source.layers
    | ..
    | select(type == "object")
    | ."_ws.expert"
    | select(. != null)
    | select(."_ws.expert.severity" == "8388608" and ."_ws.expert.group" == "16777216");
[csum_errors] | length'

  [ "$(tshark -r "$pcap_file" -T json -o tcp.check_checksum:TRUE | jq "$filter")" -eq 0 ]
}
