// SPDX-License-Identifier: GPL-2.0
// Ratatoskr tc/clsact egress: IPv4 policy selection and collect_md GENEVE.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MODE_FULL 0
#define MODE_INCLUDE 1
#define MODE_EXCLUDE 2
#define MODE_LOCKDOWN 3
#define REASON_NO_ENDPOINT 0
#define REASON_TUNNEL_KEY 1
#define REASON_TUNNEL_OPT 2
#define REASON_REDIRECT 3
#define REASON_METADATA 4
#define REASON_BAD_CONFIG 5
#define REASON_LOCKDOWN 6
#define MAX_RULES 64
#define MAX_EXCLUSIONS 1024

struct lpm_v4 { __u32 prefixlen; __u32 addr; };
struct lpm_rule { __u32 prefixlen; __u32 rule; __u32 addr; };
struct port_key { __u32 rule; __u16 port; __u8 proto; __u8 pad; };
struct rule_info { __u8 active; __u8 any_dst; __u8 any_port; __u8 pad; };
struct client_config {
 __u32 pod_ip; __u32 endpoint; __u32 gateway_id; __u32 ifindex;
 __u32 mode; __u32 healthy; __u32 allow_metadata;
 __u8 gateway_mac[6]; __u8 pad[2];
};
struct geneve_opt { __be16 cls; __u8 type; __u8 len; __u8 identity[8]; };

struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, MAX_EXCLUSIONS); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, struct lpm_v4); __type(value, __u8); } exclude_v4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 4096); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, struct lpm_rule); __type(value, __u8); } include_v4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, struct port_key); __type(value, __u8); } port_rules SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, MAX_RULES); __type(key, __u32); __type(value, struct rule_info); } rules SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct client_config); } config SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct geneve_opt); } identity SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 7); __type(key, __u32); __type(value, __u64); } stats SEC(".maps");

static __always_inline void count(__u32 reason) {
 __u64 *counter = bpf_map_lookup_elem(&stats, &reason);
 if (counter) __sync_fetch_and_add(counter, 1);
}
static __always_inline int matched(__u32 dst, __u8 proto, __u16 port) {
 // One map key per policy rule: the kernel verifier can constant-fold each
 // unrolled branch without relying on bounded-loop state widening in 5.10.
#pragma clang loop unroll(full)
 for (int i=0; i<MAX_RULES; i++) {
  __u32 id=i;
  struct rule_info *r=bpf_map_lookup_elem(&rules,&id);
  if (!r || !r->active) continue;
  if (!r->any_dst) {
   struct lpm_rule k={.prefixlen=64,.rule=id,.addr=dst};
   if (!bpf_map_lookup_elem(&include_v4,&k)) continue;
  }
  if (!r->any_port) {
   struct port_key key={.rule=id,.port=port,.proto=proto};
   if (!bpf_map_lookup_elem(&port_rules,&key)) continue;
  }
  return 1;
 }
 return 0;
}
SEC("tc")
int steer(struct __sk_buff *skb) {
 __u32 zero=0;
 struct client_config *c=bpf_map_lookup_elem(&config,&zero);
 if (!c) {count(REASON_BAD_CONFIG);return TC_ACT_SHOT;}
 void *data=(void *)(long)skb->data, *end=(void *)(long)skb->data_end;
 struct ethhdr *eth=data;
 if ((void *)(eth+1)>end) return TC_ACT_SHOT;
 if (eth->h_proto==bpf_htons(ETH_P_IPV6)) return TC_ACT_SHOT; // IPv6 v1 non-goal: no unsteered leak.
 if (eth->h_proto!=bpf_htons(ETH_P_IP)) return TC_ACT_OK;
 if (c->mode==MODE_LOCKDOWN) {count(REASON_LOCKDOWN);return TC_ACT_SHOT;}
 struct iphdr *iph=(void *)(eth+1);
 if ((void *)(iph+1)>end) return TC_ACT_SHOT;
 if (iph->ihl!=5) return TC_ACT_SHOT; // never bypass selectors on IPv4 options/malformed headers
 __u32 dst=iph->daddr;
 if (dst==bpf_htonl(0xa9fea9fe) && !c->allow_metadata) {count(REASON_METADATA);return TC_ACT_SHOT;}
 struct lpm_v4 excluded={.prefixlen=32,.addr=dst};
 if (bpf_map_lookup_elem(&exclude_v4,&excluded)) return TC_ACT_OK;
 int selected=c->mode==MODE_FULL;
 if (c->mode==MODE_INCLUDE || c->mode==MODE_EXCLUDE) {
  __u8 proto=iph->protocol; __u16 port=0;
  if (proto==IPPROTO_TCP || proto==IPPROTO_UDP) {
   __u32 ihl=(__u32)iph->ihl*4;
   if (data+sizeof(*eth)+ihl+4<=end && !(bpf_ntohs(iph->frag_off)&0x1fff)) {
    __be16 *dport=data+sizeof(*eth)+ihl+2;
    port=bpf_ntohs(*dport);
   }
  }
  int hit=matched(dst,proto,port);
  selected=c->mode==MODE_INCLUDE ? hit : !hit;
 }
 // Non-initial fragments have no L4 ports: prevent split route decisions.
 if ((bpf_ntohs(iph->frag_off)&0x1fff) && (c->mode==MODE_INCLUDE || c->mode==MODE_EXCLUDE)) return TC_ACT_SHOT;
 if (!selected) return TC_ACT_OK;
 if (!c->healthy || !c->endpoint || !c->ifindex) {count(REASON_NO_ENDPOINT);return TC_ACT_SHOT;}
 struct bpf_tunnel_key tun={};
 tun.tunnel_id=c->gateway_id;
 tun.remote_ipv4=c->endpoint;
 // Linux 5.10 bpf_tunnel_key has no local_ipv4 member. The endpoint's
 // main-table route must source c->pod_ip (checked before attaching tc).
 tun.tunnel_ttl=64;
 if (bpf_skb_set_tunnel_key(skb,&tun,offsetof(struct bpf_tunnel_key,local_ipv4),0)<0) {count(REASON_TUNNEL_KEY);return TC_ACT_SHOT;}
 struct geneve_opt *opt=bpf_map_lookup_elem(&identity,&zero);
 if (!opt || bpf_skb_set_tunnel_opt(skb,opt,sizeof(*opt))<0) {count(REASON_TUNNEL_OPT);return TC_ACT_SHOT;}
 if (bpf_skb_store_bytes(skb,offsetof(struct ethhdr,h_dest),c->gateway_mac,6,0)<0) {count(REASON_REDIRECT);return TC_ACT_SHOT;}
 return bpf_redirect(c->ifindex,0);
}
char LICENSE[] SEC("license")="GPL";
