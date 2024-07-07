#!/bin/bash
[ "${BASH_SOURCE[0]}" = "$0" ] && set -e

br=br-mimic-bench
netns=(mimic-bench-{1..2})

veth=(veth-mimic-{1..2})
veth_ipv4_range=169.254.100.0/24
veth_ipv4=(169.254.100.{1..2}/24)
veth_ipv6_range=fc10::/64
veth_ipv6=(fc10::{1..2}/64)

wg_port=(1100{1..2})
wg_ipv4_range=169.254.200.0/24
wg_ipv4=(169.254.200.{1..2}/24)
wg_ipv6_range=fc20::/64
wg_ipv6=(fc20::{1..2}/64)

max=$((${#netns[@]} - 1))

strip_ip_cidr() {
  sed 's/\/[0-9]\+$//' <(echo "$1")
}

test_env_setup() {
  for _i in "$@"; do
    case "$_i" in
      --wg) local wg=1;;
      --wg-v4) local wg_ip_kind=v4;;
      --wg-v6) local wg_ip_kind=v6;;
      --wg-mtu=*) local wg_mtu="${_i#*=}";;
      --no-offload) local no_offload=true;;
      *) ;;
    esac
  done

  ip link add $br type bridge
  # ip link set $br mtu 9000
  ip link set $br up

  for _i in `seq 0 $max`; do
    ip netns add ${netns[$_i]}
    ip link add ${veth[$_i]} type veth peer ${veth[$_i]} netns ${netns[$_i]}
    ip link set ${veth[$_i]} master $br
    # ip link set ${veth[$_i]} mtu 9000
    ip -n ${netns[$_i]} addr add dev ${veth[$_i]} ${veth_ipv4[$_i]}
    ip -n ${netns[$_i]} addr add dev ${veth[$_i]} ${veth_ipv6[$_i]}
    # ip -n ${netns[$_i]} link set ${veth[$_i]} mtu 9000
    ip link set ${veth[$_i]} up
    [ "$no_offload" != true ] || ip netns exec ${netns[$_i]} ethtool -K ${veth[$_i]} tx off
    ip -n ${netns[$_i]} link set ${veth[$_i]} up
  done

  if [ -n "$wg" ]; then
    local _priv_key=(`wg genkey` `wg genkey`)
    for _i in `seq 0 $max`; do
      ip -n ${netns[$_i]} link add wg-${veth[$_i]} type wireguard
      ip -n ${netns[$_i]} addr add dev wg-${veth[$_i]} ${wg_ipv4[$_i]}
      ip -n ${netns[$_i]} addr add dev wg-${veth[$_i]} ${wg_ipv6[$_i]}

      ip netns exec ${netns[$_i]} wg set wg-${veth[$_i]} \
          listen-port ${wg_port[$_i]} \
          private-key <(echo ${_priv_key[$_i]})

      for _j in `seq 0 $max`; do
        if [ $_i -eq $_j ]; then continue; fi
        local _endpoint
        if [ "$wg_ip_kind" = v6 ]; then
          _endpoint=\[`strip_ip_cidr ${veth_ipv6[$_j]}`\]
        else
          _endpoint=`strip_ip_cidr ${veth_ipv4[$_j]}`
        fi
        ip netns exec ${netns[$_i]} wg set wg-${veth[$_i]} \
          peer `echo ${_priv_key[$_j]} | wg pubkey` \
          allowed-ips ${wg_ipv4_range},${wg_ipv6_range} \
          endpoint $_endpoint:${wg_port[$_j]}
      done

      if [ -n "$wg_mtu" ]; then
      echo set mtu to $wg_mtu
        ip -n ${netns[$_i]} link set wg-${veth[$_i]} mtu "$wg_mtu"
      fi

      ip -n ${netns[$_i]} link set wg-${veth[$_i]} up
    done
  fi
}

test_env_cleanup() (
  set +e
  ip link del $br
  for _i in `seq 0 $max`; do
    ip netns del ${netns[$_i]}
    ip link del ${veth[$_i]} 2>/dev/null
  done
)

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
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
fi
