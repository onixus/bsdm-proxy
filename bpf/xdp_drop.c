// eBPF XDP Packet Drop Filter for BSDM Proxy
// Drops IP packets from blacklisted IP addresses at the NIC driver layer (XDP_DROP).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 address in network byte order
    __type(value, __u8);  // 1 = block
} bsdm_blocked_ips SEC(".maps");

SEC("xdp")
int xdp_drop_blocked_ips(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&bsdm_blocked_ips, &src_ip);
    if (blocked && *blocked == 1) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
