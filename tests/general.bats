#!/usr/bin/env bats

BATS_TEST_RETRIES=2
BATS_NO_PARALLELIZE_WITHIN_FILE=true

: "${SLEEP_MULTIPLIER:=1}"
if [ "$SLEEP_MULTIPLIER" -lt 1 ]; then
  >&2 echo SLEEP_MULTIPLIER cannot be less than 1
  exit 1
fi

load helpers/env

pcap_file="$BATS_RUN_TMPDIR/general.pcapng"
pcap_file_dest="$BATS_TEST_DIRNAME/../out/general.pcapng"
fifo=("$BATS_RUN_TMPDIR/"{1..2}.pipe)
output=("$BATS_RUN_TMPDIR/"{1..2}.output)
fifo_pid=()
socat_pid=()
mimic_pid=()

setup_file() {
  [ "$UID" -eq 0 ] || skip
  test_env_setup --no-offload

  # Wait for netns to take effect, otherwise tests will probably hang
  sleep $(( 2 * SLEEP_MULTIPLIER ))

  # Tshark will terminate itself when bridge is removed
  tshark -i $br -w "$pcap_file" &
}

teardown_file() {
  test_env_cleanup
  cp "$pcap_file" "$pcap_file_dest"
  chmod +r "$pcap_file_dest"
}

setup() {
  mkfifo ${fifo[@]}
  for _i in `seq 0 $max`; do
    sleep infinity > ${fifo[$_i]} &
    fifo_pid[$_i]=$!
  done
}

teardown() {
  kill -9 ${fifo_pid[@]} 2> /dev/null
  kill -INT ${socat_pid[@]} ${mimic_pid[@]} 2> /dev/null
  wait ${mimic_pid[@]}
  rm -f ${fifo[@]} ${output[@]}
}

_generate_port() {
  echo $(( SRANDOM % (65536 - 10000) + 10000 ))
}

_setup_mimic_socat() {
  local port=(`_generate_port` `_generate_port`)

  for _i in `seq 0 $max`; do
    local opposite=$(( 1 - $_i ))
    if [ "$1" = v6 ]; then
      local self_ip_port="[`strip_ip_cidr ${veth_ipv6[$_i]}`]:${port[$_i]}"
      local opposite_ip_port="[`strip_ip_cidr ${veth_ipv6[$opposite]}`]:${port[$opposite]}"
    else
      local self_ip_port="`strip_ip_cidr ${veth_ipv4[$_i]}`:${port[$_i]}"
      local opposite_ip_port="`strip_ip_cidr ${veth_ipv4[$opposite]}`:${port[$opposite]}"
    fi

    ip netns exec ${netns[$_i]} "$BATS_TEST_DIRNAME/../out/mimic" \
      run ${veth[$_i]} -flocal="$self_ip_port" \
      & mimic_pid[$_i]=$!
    echo "$! is mimic"

    # FIXME: Sometimes the second socat will exit without any messages
    ip netns exec ${netns[$_i]} socat - \
      "udp:$opposite_ip_port,bind=$self_ip_port" \
      < ${fifo[$_i]} > ${output[$_i]} \
      & socat_pid[$_i]=$!
    echo "$! is socat"
  done

  # Wait for socat and mimic to set up
  sleep $(( 5 * SLEEP_MULTIPLIER ))
}

# Check Mimic is still running.
#
# Because Mimic layers UDP traffic transparently, when both ends fails to run
# Mimic, the result will still be correct.
_check_mimic_is_alive() {
  for _i in `seq 0 $max`; do
    ps -p ${mimic_pid[$_i]} > /dev/null
  done
}

_test_random_traffic() {
  _setup_mimic_socat "$1"
  for _i in {0..499}; do
    head -c $(( SRANDOM % 1400 )) /dev/urandom >> ${fifo[$(( RANDOM % 2 ))]}
    sleep $(echo "0.001 * $SLEEP_MULTIPLIER * ($RANDOM % 10)" | bc -l)
  done
  _check_mimic_is_alive
}

@test "test Mimic against some random UDP traffic (IPv4)" {
  _test_random_traffic v4
}

@test "test Mimic against some random UDP traffic (IPv6)" {
  _test_random_traffic v6
}

_test_packet_buffer() {
  _setup_mimic_socat "$1"

  # Send multiple packets of random data in a short time (hopefully before
  # handshake)
  local random_data=()
  for _i in {0..5}; do
    random_data[$_i]="`head -c $(( SRANDOM % 1400 )) /dev/urandom`"
    echo "${random_data[$_i]}" >> ${fifo[0]}
  done

  # Wait for transmission
  sleep $(( 1 * SLEEP_MULTIPLIER ))

  # Check if all sent data are present
  [ "$(cat ${output[1]})" = "$(printf '%s\n' "${random_data[@]}")" ]
  _check_mimic_is_alive
}

@test "test if packets before handshake is stored and re-sent afterwards (IPv4)" {
  _test_packet_buffer v4
}

@test "test if packets before handshake is stored and re-sent afterwards (IPv6)" {
  _test_packet_buffer v6
}

@test "test if there is no error detected in packet capture, especially checksum" {
  run tshark -r "$pcap_file" -z expert,error -q -o tcp.check_checksum:TRUE
  if [ -n "$(grep Errors <<< "$output")" ]; then
    echo "$output"
    false
  fi
}
