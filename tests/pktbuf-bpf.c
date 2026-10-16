#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdio.h>

#include "common/defs.h"
#include "src/bpf_skel.h"

#define TEST_PKTBUF 1234

static unsigned int releases;
static unsigned int control_packets;
static bool expect_control;
static enum rb_item_type release_type;

static int handle_event(void* ctx, void* data, size_t len) {
  UNUSED(ctx);
  assert(len >= sizeof(struct rb_item));
  struct rb_item* item = data;
  if (item->type == RB_ITEM_SEND_OPTIONS) control_packets++;
  if (item->type == RB_ITEM_CONSUME_PKTBUF || item->type == RB_ITEM_FREE_PKTBUF) {
    if (expect_control) assert(control_packets > 0);
    assert(item->pktbuf == TEST_PKTBUF);
    releases++;
    release_type = item->type;
  }
  return 0;
}

int main(void) {
  struct mimic_bpf* skel = mimic_bpf__open();
  assert(skel);
  skel->bss->link_type = LINK_ETH;
  skel->bss->log_verbosity = -1;
  assert(bpf_map__set_max_entries(skel->maps.mimic_rb, 4096) == 0);
  assert(mimic_bpf__load(skel) == 0);
  struct ring_buffer* rb =
    ring_buffer__new(bpf_map__fd(skel->maps.mimic_rb), handle_event, NULL, NULL);
  assert(rb);

  struct {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
  } __attribute__((packed)) pkt = {
    .eth.h_proto = htons(ETH_P_IP),
    .ip = {.ihl = 5,
           .version = 4,
           .tot_len = htons(40),
           .protocol = IPPROTO_TCP,
           .saddr = inet_addr("192.0.2.2"),
           .daddr = inet_addr("192.0.2.1")},
    .tcp = {.source = htons(12002),
            .dest = htons(12001),
            .doff = 5,
            .seq = htonl(100),
            .ack_seq = htonl(200)},
  };
  struct conn_tuple key = {.local = ipv4_mapped(pkt.ip.daddr),
                           .remote = ipv4_mapped(pkt.ip.saddr),
                           .local_port = 12001,
                           .remote_port = 12002};
  struct filter f = {.origin = O_LOCAL, .ip = key.local, .port = key.local_port};
  struct filter_info info = {.settings = DEFAULT_SETTINGS};
  int conns_fd = bpf_map__fd(skel->maps.mimic_conns);
  int prog_fd = bpf_program__fd(skel->progs.ingress_handler);
  assert(bpf_map__update_elem(skel->maps.mimic_whitelist, &f, sizeof(f), &info, sizeof(info),
                              BPF_ANY) == 0);
  LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = &pkt, .data_size_in = sizeof(pkt));
  const struct {
    enum conn_state before, after;
    __be32 flags;
    enum rb_item_type event;
  } cases[] = {
    {CONN_SYN_SENT, CONN_ESTABLISHED, TCP_FLAG_SYN | TCP_FLAG_ACK, RB_ITEM_CONSUME_PKTBUF},
    {CONN_SYN_RECV, CONN_ESTABLISHED, TCP_FLAG_ACK, RB_ITEM_CONSUME_PKTBUF},
    {CONN_SYN_SENT, CONN_IDLE, TCP_FLAG_RST, RB_ITEM_FREE_PKTBUF},
    {CONN_SYN_RECV, CONN_IDLE, TCP_FLAG_FIN, RB_ITEM_FREE_PKTBUF},
    {CONN_IDLE, CONN_IDLE, TCP_FLAG_ACK, RB_ITEM_FREE_PKTBUF},
  };

  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    // Access the flag word through an aligned header, then copy it into the packed packet.
    struct tcphdr tcp = pkt.tcp;
    struct connection conn = conn_init(&info.settings, 0);
    conn.state = CONN_SYN_SENT;
    conn.seq = 200;
    tcp_flag_word(&tcp) = TCP_FLAG_SYN | TCP_FLAG_ACK;
    tcp.doff = 5;
    pkt.tcp = tcp;
    // Fill the ring with control packet events, without consuming them.
    for (int i = 0; i < 100; i++) {
      assert(bpf_map_update_elem(conns_fd, &key, &conn, BPF_ANY) == 0);
      assert(bpf_prog_test_run_opts(prog_fd, &opts) == 0);
    }

    conn.state = cases[c].before;
    conn.pktbuf = TEST_PKTBUF;
    tcp_flag_word(&tcp) = cases[c].flags;
    tcp.doff = 5;
    pkt.tcp = tcp;
    assert(bpf_map_update_elem(conns_fd, &key, &conn, BPF_ANY) == 0);
    assert(bpf_prog_test_run_opts(prog_fd, &opts) == 0);
    assert(bpf_map_lookup_elem_flags(conns_fd, &key, &conn, BPF_F_LOCK) == 0);
    assert(conn.pktbuf == TEST_PKTBUF && conn.state == cases[c].before);
    assert(ring_buffer__consume(rb) >= 0);
    assert(releases == c);

    // After the consumer catches up, retrying must transfer ownership once.
    control_packets = 0;
    expect_control = cases[c].before == CONN_SYN_SENT && cases[c].after == CONN_ESTABLISHED;
    assert(bpf_prog_test_run_opts(prog_fd, &opts) == 0);
    assert(bpf_map_lookup_elem_flags(conns_fd, &key, &conn, BPF_F_LOCK) == 0);
    assert(conn.pktbuf == 0 && conn.state == cases[c].after);
    assert(ring_buffer__consume(rb) >= 0);
    assert(releases == c + 1 && release_type == cases[c].event);
  }

  ring_buffer__free(rb);
  mimic_bpf__destroy(skel);
  puts("BPF packet buffer ownership tests passed");
  return 0;
}
