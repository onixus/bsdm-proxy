// eBPF XDP Packet Drop Filter for BSDM Proxy
// Drops IP packets from blacklisted IPv4 and IPv6 addresses at the NIC driver layer (XDP_DROP)
// and records drop statistics in kernel maps.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Per-address drop counters. Presence of an entry means "block this source";
// the value accumulates what was actually dropped for it. Userspace
// (proxy/src/ebpf.rs) inserts entries with both counters zeroed and reads them
// back via `bpftool map dump`.
struct ip_drop_stats {
    __u64 packets;
    __u64 bytes;
};

// IPv4 blocked addresses: key is 32-bit IPv4 in network byte order
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct ip_drop_stats);
} bsdm_blocked_ips SEC(".maps");

// IPv6 blocked addresses: key is 128-bit IPv6 address
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct in6_addr);
    __type(value, struct ip_drop_stats);
} bsdm_blocked_ips_v6 SEC(".maps");

// Drop statistics array:
// index 0 = total dropped packets count
// index 1 = total dropped bytes count
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} bsdm_drop_stats SEC(".maps");

static __always_inline void record_drop(__u64 pkt_len) {
    __u32 key_pkts = 0;
    __u64 *pkts = bpf_map_lookup_elem(&bsdm_drop_stats, &key_pkts);
    if (pkts) {
        __sync_fetch_and_add(pkts, 1);
    }

    __u32 key_bytes = 1;
    __u64 *bytes = bpf_map_lookup_elem(&bsdm_drop_stats, &key_bytes);
    if (bytes) {
        __sync_fetch_and_add(bytes, pkt_len);
    }
}

SEC("xdp")
int xdp_drop_blocked_ips(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = __builtin_bswap16(eth->h_proto);

    // IPv4 packet inspection
    if (h_proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __u32 src_ip = iph->saddr;
        struct ip_drop_stats *blocked = bpf_map_lookup_elem(&bsdm_blocked_ips, &src_ip);
        if (blocked) {
            __u64 pkt_len = (long)data_end - (long)data;
            __sync_fetch_and_add(&blocked->packets, 1);
            __sync_fetch_and_add(&blocked->bytes, pkt_len);
            record_drop(pkt_len);
            return XDP_DROP;
        }
    }
    // IPv6 packet inspection
    else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        struct in6_addr src_ip6 = ip6h->saddr;
        struct ip_drop_stats *blocked = bpf_map_lookup_elem(&bsdm_blocked_ips_v6, &src_ip6);
        if (blocked) {
            __u64 pkt_len = (long)data_end - (long)data;
            __sync_fetch_and_add(&blocked->packets, 1);
            __sync_fetch_and_add(&blocked->bytes, pkt_len);
            record_drop(pkt_len);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
