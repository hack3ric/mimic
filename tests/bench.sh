#!/bin/bash
# Simple script for benchmarking Mimic
set -e

_netns=mimic-bench
_veth1=veth-bench-1
_veth2=veth-bench-2
_veth_ip1=169.254.100.1
_veth_ip2=169.254.100.2
_wg_ip1=169.254.200.1
_wg_ip2=169.254.200.2
_mimic1=
_mimic2=

_curdir=$(dirname $(realpath "${BASH_SOURCE[0]}"))

setup() {
  ip netns add $_netns

  ip link add $_veth1 type veth peer name $_veth2
  ip link set $_veth2 netns $_netns

  ip addr add $_veth_ip1/30 dev $_veth1
  ip netns exec $_netns ip addr add $_veth_ip2/30 dev $_veth2

  ip link set $_veth1 up
  ip netns exec $_netns ip link set $_veth2 up

  local _host_priv_key=$(wg genkey)
  local _ns_priv_key=$(wg genkey)

  ip link add wg-$_veth1 type wireguard
  wg set wg-$_veth1 listen-port 11001 private-key <(echo $_host_priv_key)
  ip addr add $_wg_ip1/32 dev wg-$_veth1 peer $_wg_ip2
  wg set wg-$_veth1 peer $(echo $_ns_priv_key | wg pubkey) allowed-ips $_wg_ip2 endpoint $_veth_ip2:11002
  ip link set wg-$_veth1 up

  ip netns exec $_netns ip link add wg-$_veth2 type wireguard
  ip netns exec $_netns wg set wg-$_veth2 listen-port 11002 private-key <(echo $_ns_priv_key)
  ip netns exec $_netns ip addr add $_wg_ip2/32 dev wg-$_veth2 peer $_wg_ip1
  ip netns exec $_netns wg set wg-$_veth2 peer $(echo $_host_priv_key | wg pubkey) allowed-ips $_wg_ip1 endpoint $_veth_ip1:11001
  ip netns exec $_netns ip link set wg-$_veth2 up

  if [ "$1" = "mimic" ]; then
    "$_curdir/../out/mimic" run $_veth1 -flocal=$_veth_ip1:11001 & _mimic1=$!
    ip netns exec $_netns "$_curdir/../out/mimic" run $_veth2 -flocal=$_veth_ip2:11002 & _mimic2=$!
    sleep 1
  fi
}

bench() {
  local _tmp="$(mktemp)"
  local _type="$1"; shift
  local _dest=

  if [ "$_type" = "veth" ]; then
    _dest=$_veth_ip2
  else
    _dest=$_wg_ip2
  fi

  # Workaround for Mimic throwing away first packet
  ping -c1 $_wg_ip2

  ip netns exec $_netns iperf3 -s -D -I "$_tmp"
  iperf3 -c $_dest $@
  kill $(cat $_tmp)
}

cleanup() {
  [ -z $_mimic1 ] || kill $_mimic1
  [ -z $_mimic2 ] || kill $_mimic2
  wait
  ip netns delete $_netns
  ip link delete $_veth1
  ip link delete wg-$_veth1
}

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

setup $_type
bench $_type $@
cleanup
