#!/usr/bin/env bash
set -e

_br=br-mimic-bench
_netns=(mimic-bench-{1..2})

_veth=(veth-mimic-{1..2})
_veth_ipv4_range=169.254.100.0/24
_veth_ipv4=(169.254.100.{1..2}/24)
_veth_ipv6_range=fc10::/64
_veth_ipv6=(fc10::{1..2}/64)

_wg_port=(1100{1..2})
_wg_ipv4_range=169.254.200.0/24
_wg_ipv4=(169.254.200.{1..2}/24)
_wg_ipv6_range=fc20::/64
_wg_ipv6=(fc20::{1..2}/64)

_ipv6=

_max=$((${#_netns[@]} - 1))

test_env_setup() {
  ip link add $_br type bridge
  ip link set $_br up

  for _i in `seq 0 $_max`; do
    ip netns add ${_netns[$_i]}
    ip link add ${_veth[$_i]} type veth peer ${_veth[$_i]} netns ${_netns[$_i]}
    ip link set ${_veth[$_i]} master $_br
    ip -n ${_netns[$_i]} addr add dev ${_veth[$_i]} ${_veth_ipv4[$_i]}
    ip -n ${_netns[$_i]} addr add dev ${_veth[$_i]} ${_veth_ipv6[$_i]}
    ip link set ${_veth[$_i]} up
    ip -n ${_netns[$_i]} link set ${_veth[$_i]} up
  done

  if [ "$1" = wg ]; then
    shift
    local _priv_key=(`wg genkey` `wg genkey`)
    for _i in `seq 0 $_max`; do
      ip -n ${_netns[$_i]} link add wg-${_veth[$_i]} type wireguard
      ip -n ${_netns[$_i]} addr add dev wg-${_veth[$_i]} ${_wg_ipv4[$_i]}
      ip -n ${_netns[$_i]} addr add dev wg-${_veth[$_i]} ${_wg_ipv6[$_i]}

      ip netns exec ${_netns[$_i]} wg set wg-${_veth[$_i]} \
          listen-port ${_wg_port[$_i]} \
          private-key <(echo ${_priv_key[$_i]})

      for _j in `seq 0 $_max`; do
        if [ $_i -eq $_j ]; then continue; fi
        local _endpoint
        if [ -n "$_ipv6" ]; then
          _endpoint=\[`sed 's/\/[0-9]\+$//' <(echo ${_veth_ipv6[$_j]})`\]
        else
          _endpoint=`sed 's/\/[0-9]\+$//' <(echo ${_veth_ipv4[$_j]})`
        fi
        ip netns exec ${_netns[$_i]} wg set wg-${_veth[$_i]} \
          peer `echo ${_priv_key[$_j]} | wg pubkey` \
          allowed-ips ${_wg_ipv4_range},${_wg_ipv6_range} \
          endpoint $_endpoint:${_wg_port[$_j]}
      done

      ip -n ${_netns[$_i]} link set wg-${_veth[$_i]} up
    done
  fi
}

test_env_cleanup() (
  set +e
  ip link del $_br
  for _i in `seq 0 $_max`; do
    ip netns del ${_netns[$_i]}
  done
)

case "$1" in
  setup)
    shift
    test_env_setup $@
    ;;
  clean)
    shift
    test_env_cleanup $@
    ;;
  *)
    >&2 echo "expected 'setup' or 'clean'"
    exit 1
    ;;
esac
