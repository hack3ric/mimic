#!/usr/bin/env bats

load env.sh

tshark_pid=

fifo=("$BATS_RUN_TMPDIR/"{1..2}.pipe)
output=("$BATS_RUN_TMPDIR/"{1..2}.output)
fifo_pid=()
socat_pid=()
mimic_pid=()

setup_file() {
  test_env_setup
  tshark -i $br -w "$BATS_RUN_TMPDIR/out.pcapng" 2>&3 & tshark_pid=$!
}

teardown_file() {
  kill -INT $tshark_pid || true
  test_env_cleanup
  mv "$BATS_RUN_TMPDIR/out.pcapng" "$BATS_TEST_DIRNAME"
  chmod +r "$BATS_TEST_DIRNAME/out.pcapng"
}

setup() {
  mkfifo ${fifo[@]}
  for _i in `seq 0 $max`; do
    ( sleep infinity ) >${fifo[$_i]} &
    fifo_pid[$_i]=$!
  done

  # Wait for netns to take effect
  sleep 2
}

teardown() {
  kill -INT ${fifo_pid[@]} ${socat_pid[@]} ${mimic_pid[@]} || true
  rm -f ${fifo[@]} ${output[@]} || true
}

@test "transmit random data through Mimic" {
  local port=(4500{1..2})
  local random_data=()

  for _i in `seq 0 $max`; do
    random_data[$_i]=`cat /dev/urandom | base64 -w0 | head -c $(( SRANDOM % 1400 + 1 ))`

    ip netns exec ${netns[$_i]} "$BATS_TEST_DIRNAME/../out/mimic" run ${veth[$_i]} \
      "-flocal=[`strip_ip_cidr ${veth_ipv6[$_i]}`]:${port[$_i]}" 2>&3 \
      & mimic_pid[$_i]=$!

    local opposite=$(( 1 - $_i ))
    ip netns exec ${netns[$_i]} socat \
      "udp:[`strip_ip_cidr ${veth_ipv6[$opposite]}`]:${port[$opposite]},bind=[`strip_ip_cidr ${veth_ipv6[$_i]}`]:${port[$_i]}" - \
      <${fifo[$_i]} >${output[$_i]} 2>&3 \
      & socat_pid[$_i]=$!
  done

  # Wait for socat and mimic to set up
  sleep 1

  echo "${random_data[0]}" > ${fifo[0]}
  sleep 0.1
  echo "${random_data[1]}" > ${fifo[1]}

  # Wait for transmission
  sleep 1

  [ "`cat ${output[0]}`" = "${random_data[1]}" ] || [ -z "`cat ${output[0]}`" ]
  [ "`cat ${output[1]}`" = "${random_data[0]}" ] || [ -z "`cat ${output[1]}`" ]
}
