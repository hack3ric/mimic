_setup() {
  mkfifo ${fifo[@]}
  for _i in {0..1}; do
    sleep infinity >${fifo[$_i]} &
    fifo_pid[$_i]=$!
  done
}

_teardown() {
  kill -9 ${fifo_pid[@]} 2>/dev/null
  kill -INT ${socat_pid[@]} ${mimic_pid[@]} 2>/dev/null
  wait ${mimic_pid[@]}
  rm -f ${fifo[@]} ${output[@]}
}

generate_port() {
  echo $((SRANDOM % (65536 - 10000) + 10000))
}

strip_ip_cidr() {
  sed 's/\/[0-9]\+$//' <(echo "$1")
}

setup_mimic_socat() {
  local port=($(generate_port) $(generate_port))

  for _i in {0..1}; do
    local _o=$((1 - $_i))
    if [ "$1" = v6 ]; then
      local self_ip_port="[$(strip_ip_cidr ${veth_ipv6[$_i]})]:${port[$_i]}"
      local opposite_ip_port="[$(strip_ip_cidr ${veth_ipv6[$_o]})]:${port[$_o]}"
    else
      local self_ip_port="$(strip_ip_cidr ${veth_ipv4[$_i]}):${port[$_i]}"
      local opposite_ip_port="$(strip_ip_cidr ${veth_ipv4[$_o]}):${port[$_o]}"
    fi

    ip netns exec ${netns[$_i]} "$BATS_TEST_DIRNAME/../out/mimic" \
      run ${veth[$_i]} -flocal="$self_ip_port" \
      &
    mimic_pid[$_i]=$!
    echo "$! is mimic"

    # FIXME: Sometimes the second socat will exit without any messages
    ip netns exec ${netns[$_i]} socat - \
      "udp:$opposite_ip_port,bind=$self_ip_port" \
      <${fifo[$_i]} >${output[$_i]} \
      &
    socat_pid[$_i]=$!
    echo "$! is socat"
  done

  # Wait for socat and mimic to set up
  sleep $((5 * SLEEP_MULTIPLIER))
}

# Check Mimic is still running.
#
# Because Mimic layers UDP traffic transparently, when both ends fails to run
# Mimic, the result will still be correct.
check_mimic_is_alive() {
  for _i in {0..1}; do
    ps -p ${mimic_pid[$_i]} >/dev/null
  done
}
