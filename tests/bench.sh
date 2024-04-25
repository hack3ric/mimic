#!/bin/bash
set -e

_curdir=$(dirname $(realpath "${BASH_SOURCE[0]}"))
. "$_curdir/env.sh"

setup() {
  test_env_setup --wg --wg-v6 --wg-mtu=1408

  if [ "$1" = "mimic" ]; then
    for _i in `seq 0 $max`; do
      ip netns exec ${netns[$_i]} "$_curdir/../out/mimic" run ${veth[$_i]} \
        "-flocal=[`strip_ip_cidr ${veth_ipv6[$_i]}`]:${wg_port[$_i]}" & _mimic[$_i]=$!
    done
    sleep 1
  fi
}

bench() {
  local _type="$1"; shift

  local _dest
  if [ "$_type" = "veth" ]; then
    _dest=`strip_ip_cidr ${veth_ipv6[0]}`
  else
    _dest=`strip_ip_cidr ${wg_ipv6[0]}`
  fi

  _iperf3_pid_tmp=`mktemp`
  ip netns exec ${netns[0]} iperf3 -s -D -I "$_iperf3_pid_tmp"
  ip netns exec ${netns[1]} iperf3 -c $_dest $@
}

cleanup() (
  set +e
  for _i in `seq 0 $max`; do
    [ -z ${_mimic[$_i]} ] || kill ${_mimic[$_i]}
  done
  wait
  if [ -n "$_iperf3_pid_tmp" ]; then
    kill `cat $_iperf3_pid_tmp`
  fi
  test_env_cleanup
)

case "$1" in
  clean | cleanup)
    cleanup
    exit
    ;;
  veth | wg | mimic)
    _type=$1
    shift
    ;;
  *)
    _type=mimic
    ;;
esac

trap cleanup SIGINT
setup $_type
bench $_type $@
cleanup
