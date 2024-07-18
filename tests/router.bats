#!/usr/bin/env bats

BATS_TEST_RETRIES=2
BATS_NO_PARALLELIZE_WITHIN_FILE=true

: "${SLEEP_MULTIPLIER:=1}"
if [ "$SLEEP_MULTIPLIER" -lt 1 ]; then
  >&2 echo SLEEP_MULTIPLIER cannot be less than 1
  exit 1
fi

load env/router

pcap_file=("$BATS_RUN_TMPDIR"/router-{1..2}.pcapng)
pcap_file_dest=("$BATS_TEST_DIRNAME"/../out/router-{1..2}.pcapng)
fifo=("$BATS_RUN_TMPDIR/"{1..2}.pipe)
output=("$BATS_RUN_TMPDIR/"{1..2}.output)
fifo_pid=()
socat_pid=()
mimic_pid=()

setup_file() {
  [ "$UID" -eq 0 ] || skip
  router_env_setup

  sleep $(( 2 * SLEEP_MULTIPLIER ))

  for _i in 0 1; do
    tshark -i ${br[$_i]} -w ${pcap_file[$_i]} &
  done
}

teardown_file() {
  router_env_cleanup
  for _i in 0 1; do
    cp "${pcap_file[$_i]}" "${pcap_file_dest[$_i]}"
    chmod +r "${pcap_file_dest[$_i]}"
  done
}

setup() {
  mkfifo ${fifo[@]}
  for _i in 0 1; do
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
  local _netns=(${netns[0]} ${netns[2]})
  local _veth=(${veth[0]} ${veth[3]})
  local _veth_ipv4=(${veth_ipv4[0]} ${veth_ipv4[3]})
  local _veth_ipv6=(${veth_ipv6[0]} ${veth_ipv6[3]})

  for _i in 0 1; do
    local opposite=$(( 1 - $_i ))
    if [ "$1" = v6 ]; then
      local self_ip_port="[`strip_ip_cidr ${_veth_ipv6[$_i]}`]:${port[$_i]}"
      local opposite_ip_port="[`strip_ip_cidr ${_veth_ipv6[$opposite]}`]:${port[$opposite]}"
    else
      local self_ip_port="`strip_ip_cidr ${_veth_ipv4[$_i]}`:${port[$_i]}"
      local opposite_ip_port="`strip_ip_cidr ${_veth_ipv4[$opposite]}`:${port[$opposite]}"
    fi

    ip netns exec ${_netns[$_i]} "$BATS_TEST_DIRNAME/../out/mimic" \
      run ${_veth[$_i]} -flocal="$self_ip_port" \
      & mimic_pid[$_i]=$!
    echo "$! is mimic"

    # FIXME: Sometimes the second socat will exit without any messages
    ip netns exec ${_netns[$_i]} socat - \
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

# TODO: try to drain window using one-sided traffic

@test "check conntrack status" {
  ip netns exec ${netns[1]} conntrack -L >&3
  # TODO: parse output
}
