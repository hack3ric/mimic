#!/bin/bash
#
#         /--------------------------------------\
#         |             Host Network             |
#         |   bridge1                  bridge2   |
#         \-----++-----------------------++------/
# /----------\  ||  /-----------------\  ||  /----------\
# |     veth1+==++==+veth2       veth3+==++==+veth4     |
# |  netns1  |      | netns2 (router) |      |  netns3  |
# \----------/      \-----------------/      \----------/

: "${TEST_NETWORK_ID:=mimicrt}"

br=("br$TEST_NETWORK_ID"{1..2})
netns_internal=("$TEST_NETWORK_ID"{1..3})

veth_internal=("veth$TEST_NETWORK_ID"{1..4})
veth_ipv4_range=(169.254.101.{0,128}/25)
veth_ipv4_internal=(169.254.101.{1,2,129,130}/25)
veth_ipv6_range=(fc11:{1..2}::/64)
veth_ipv6_internal=(fc11:{1..2}::{1..2}/64)

netns=(${netns_internal[0]} ${netns_internal[2]})
veth=(${veth_internal[0]} ${veth_internal[3]})
veth_ipv4=(${veth_ipv4_internal[0]} ${veth_ipv4_internal[3]})
veth_ipv6=(${veth_ipv6_internal[0]} ${veth_ipv6_internal[3]})

wg_port=(1101{1..2})
wg_ipv4_range=169.254.201.0/24
wg_ipv4=(169.254.201.{1..2}/24)
wg_ipv6_range=fc21::/64
wg_ipv6=(fc21::{1..2}/64)

_curdir=$(dirname $(realpath "${BASH_SOURCE[0]}"))
source "$_curdir/../util.bash"

router_env_setup() {
  for _i in "$@"; do
    case "$_i" in
    # --mtu=*) local mtu="${_i#*=}" ;;
    # --no-offload) local no_offload=true ;;
    --wg) local wg=1 ;;
    --wg-v4) local wg_ip_kind=v4 ;;
    --wg-v6) local wg_ip_kind=v6 ;;
    --wg-mtu=*) local wg_mtu="${_i#*=}" ;;
    *) ;;
    esac
  done

  for _netns in ${netns_internal[@]}; do
    ip netns add $_netns
    ip netns exec $_netns sysctl -w net.ipv4.conf.all.forwarding=1
    ip netns exec $_netns sysctl -w net.ipv6.conf.all.forwarding=1
  done

  for _i in {0..1}; do
    ip link add ${br[$_i]} type bridge
    ip link set ${br[$_i]} up

    for _j in {0..1}; do
      local _n=$((_i * 2 + _j))                    # veth index
      local _netns=${netns_internal[$((_i + _j))]} # netns where the veth should be in

      ip link add ${veth_internal[$_n]} type veth peer ${veth_internal[$_n]} netns $_netns
      ip link set ${veth_internal[$_n]} master ${br[$_i]}

      ip -n $_netns addr add dev ${veth_internal[$_n]} ${veth_ipv4_internal[$_n]}
      ip -n $_netns addr add dev ${veth_internal[$_n]} ${veth_ipv6_internal[$_n]}

      ip link set ${veth_internal[$_n]} up
      ip -n $_netns link set lo up
      ip -n $_netns link set ${veth_internal[$_n]} up
    done
  done

  sleep 3 # IPv6 addresses seem to need some warmup

  # This is a bit messy, but it basically sets correct route of the other side
  # through the "router" netns
  ip -n ${netns_internal[0]} route add ${veth_ipv4_range[1]} \
    via $(strip_ip_cidr ${veth_ipv4_internal[1]}) \
    src $(strip_ip_cidr ${veth_ipv4_internal[0]}) \
    dev ${veth_internal[0]}
  ip -n ${netns_internal[2]} route add ${veth_ipv4_range[0]} \
    via $(strip_ip_cidr ${veth_ipv4_internal[2]}) \
    src $(strip_ip_cidr ${veth_ipv4_internal[3]}) \
    dev ${veth_internal[3]}
  ip -6 -n ${netns_internal[0]} route add ${veth_ipv6_range[1]} \
    via $(strip_ip_cidr ${veth_ipv6_internal[1]}) \
    src $(strip_ip_cidr ${veth_ipv6_internal[0]}) \
    dev ${veth_internal[0]}
  ip -6 -n ${netns_internal[2]} route add ${veth_ipv6_range[0]} \
    via $(strip_ip_cidr ${veth_ipv6_internal[2]}) \
    src $(strip_ip_cidr ${veth_ipv6_internal[3]}) \
    dev ${veth_internal[3]}

  # Enable conntrack in router
  ip netns exec ${netns_internal[1]} nft -f - <<EOF
table inet filter {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state new,established,related accept
    ip protocol tcp ct state invalid reject with tcp reset
  }
}
EOF

  if [ -n "$wg" ]; then
    local _priv_key=($(wg genkey) $(wg genkey))
    for _i in {0..1}; do
      ip -n ${netns[$_i]} link add wg-${veth[$_i]} type wireguard
      ip -n ${netns[$_i]} addr add dev wg-${veth[$_i]} ${wg_ipv4[$_i]}
      ip -n ${netns[$_i]} addr add dev wg-${veth[$_i]} ${wg_ipv6[$_i]}

      ip netns exec ${netns[$_i]} wg set wg-${veth[$_i]} \
        listen-port ${wg_port[$_i]} \
        private-key <(echo ${_priv_key[$_i]})

      for _j in {0..1}; do
        if [ $_i -eq $_j ]; then continue; fi
        local _endpoint
        if [ "$wg_ip_kind" = v6 ]; then
          _endpoint=\[$(strip_ip_cidr ${veth_ipv6[$_j]})\]
        else
          _endpoint=$(strip_ip_cidr ${veth_ipv4[$_j]})
        fi
        ip netns exec ${netns[$_i]} wg set wg-${veth[$_i]} \
          peer $(echo ${_priv_key[$_j]} | wg pubkey) \
          allowed-ips ${wg_ipv4_range},${wg_ipv6_range} \
          endpoint $_endpoint:${wg_port[$_j]}
      done

      [ -z "$wg_mtu" ] || ip -n ${netns[$_i]} link set wg-${veth[$_i]} mtu "$wg_mtu"
      ip -n ${netns[$_i]} link set wg-${veth[$_i]} up
    done
  fi
}

router_env_cleanup() {
  set +e
  for _br in ${br[@]}; do
    ip link del $_br
  done
  for _netns in ${netns_internal[@]}; do
    ip netns del $_netns
  done
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -e
  case "$1" in
  setup)
    shift
    router_env_setup $@
    ;;
  clean)
    shift
    router_env_cleanup $@
    ;;
  *)
    >&2 echo "expected 'setup' or 'clean'"
    exit 1
    ;;
  esac
fi
