# Using mimic as a Forwarder

You might want to use FakeTCP for a component on an unsupported operating system, such as WireGuard on RouterOS. In this case, you can run mimic on another Linux machine (maybe a VM), and use iptables to forward the traffic. This ensures minimal performance overhead, as no userspace component is involved in the whole process.

## Configuration Example

For example, we can have a setup like this, where **Client** and **Forwarder** are on your local network, and **Server** can be a remote VPS:

```
┌─────────────┐       ┌──────────────┐         ┌─────────────┐
│  Client     │       │  Forwarder   │         │  Server     │
│  RouterOS   │       │  Linux       │         │  Linux      │
│             │       │              │         │             │
│ ┌─────────┐ │       │  ┌────────┐  │         │ ┌─────────┐ │
│ │WireGuard├─┼──UDP──┼──┤iptables│  │         │ │WireGuard│ │
│ └─────────┘ │       │  └───┬────┘  │         │ └────┬────┘ │
│             │       │      │       │         │      │      │
│             │       │  ┌───┴────┐  │         │  ┌───┴───┐  │
│             │       │  │ mimic  ├──┼─FakeTCP─┼──┤ mimic │  │
│             │       │  └────────┘  │         │  └───────┘  │
│             │       │              │         │             │
└─────────────┘       └──────────────┘         └─────────────┘
```

Let's assume that the **Client** (which runs RouterOS) have IP address `172.23.2.101`, **Forwarder** (which runs Linux and mimic, can be a VM) have IP address `172.23.2.100`, and **Server** have IP address `1.2.3.4`.

On the **Client**, we configure the WireGuard peer address to be a UDP port on the **Forwarder**, for example `172.23.2.100:1234`.

On the **Server**, we configure the WireGuard to listen on UDP port `1235`, and add a peer without an address.

### UDP forwarder configuration

On the **Forwarder**, we configure the following iptables rules to forward the traffic (install `iptables-persistent` package, and put into `/etc/iptables/rules.v4`):

```
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# This allows "request" packets towards the server be forwarded
-A FORWARD -d 1.2.3.4/32 -p udp -m udp --dport 1235 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
# This allows "response" packets from the server be forwarded
-A FORWARD -s 1.2.3.4/32 -p udp -m udp --sport 1235 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# This redirects all incoming packets on port 1234 to server
-A PREROUTING -p udp -m udp --dport 1234 -j DNAT --to-destination 1.2.3.4:1235
# This masquerades IP address for "request" packets, and vice versa for "response" packets
# i.e. mangles the source IP address from 172.23.2.101 to 172.23.2.100 for "request"
# and the destination IP address from 172.23.2.100 to 172.23.2.101 for "response"
-A POSTROUTING -d 1.2.3.4/32 -p udp -m udp --dport 1235 -j MASQUERADE

COMMIT
```

Run `systemctl restart netfilter-persistent` for these changes to iptables to take effect.

Also, enable IPv4 forwarding on the **Forwarder** by applying the following configuration in `/etc/sysctl.conf`:

```
# Uncomment this line, and then run `sysctl -p` to apply
net.ipv4.ip_forward=1
```

After applying these configuration, your connection should be able to establish **without** mimic. If not, try to get it working before trying to deploy mimic.

### Configuring mimic
Then, we configure mimic on **Forwarder** and **Server** with normal mimic configuration, except you have to set `xdp_mode` to `native` on the forwarder, due to a tricky problem that will be explained below.

```
# On Forwarder

# xdp_mode = skb will have some problems
xdp_mode = native
filter = remote=1.2.3.4:1235
```

```
# On Server
filter = local=1.2.3.4:1235
```

After starting mimic, your connection should be working in TCP, just as the connection in UDP when mimic is not started.

## xdp_mode = skb Problems

TBD
