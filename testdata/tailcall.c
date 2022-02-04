#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

// Array holding references to all eBPF programs for tail-calls
struct bpf_map_def SEC("maps") tails = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 4, // We will only be using 4: ip, ipv6
};

#define PARSE_IPv4 0
#define PARSE_IPv6 1

struct traffic_stats
{
    __u64 pkts;
    __u64 bytes;
};

// Stats on packets keyed by protocol number
bpf_map(ip_proto_stats, LRU_PERCPU_HASH, __u8, struct traffic_stats, 16, BPF_F_NO_COMMON_LRU);

SEC("xdp/ipv6")
int ipv6_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Offset to the next header
    __u64 nh_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

    // If we don't even have enough data to a ethernet frame header, drop the message
    if (data + nh_off > data_end)
    {
        return XDP_DROP;
    }

    struct ipv6hdr *iph = data;

    __u8 ipproto = iph->nexthdr;
    __u64 framesize = data_end - data;

    struct traffic_stats *stats_ptr = bpf_map_lookup_elem(&ip_proto_stats, &ipproto);
    if (stats_ptr == NULL)
    {
        // Make a new stats object
        struct traffic_stats stats = {
            .pkts = 1,
            .bytes = framesize,
        };
        bpf_map_update_elem(&ip_proto_stats, &ipproto, &stats, BPF_ANY);
    }
    else
    {
        stats_ptr->pkts++;
        stats_ptr->bytes += framesize;
    }

    return XDP_PASS;
}

SEC("xdp/ipv4")
int ipv4_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Offset to the next header
    __u64 nh_off = sizeof(struct ethhdr) + sizeof(struct iphdr);

    // If we don't even have enough data to a ethernet frame header, drop the message
    if (data + nh_off > data_end)
    {
        return XDP_DROP;
    }

    struct iphdr *iph = data;

    __u8 ipproto = iph->protocol;
    __u64 framesize = data_end - data;

    struct traffic_stats *stats_ptr = bpf_map_lookup_elem(&ip_proto_stats, &ipproto);
    if (stats_ptr == NULL)
    {
        // Make a new stats object
        struct traffic_stats stats = {
            .pkts = 1,
            .bytes = framesize,
        };
        bpf_map_update_elem(&ip_proto_stats, &ipproto, &stats, BPF_ANY);
    }
    else
    {
        stats_ptr->pkts++;
        stats_ptr->bytes += framesize;
    }

    return XDP_PASS;
}

SEC("xdp/entry")
int firewall_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Offset to the next header
    __u64 nh_off = sizeof(struct ethhdr);

    // If we don't even have enough data to a ethernet frame header, drop the message
    if (data + nh_off > data_end)
    {
        return XDP_DROP;
    }

    struct ethhdr *eth = data;
    __be16 h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_IP))
    {
        bpf_tail_call(ctx, &tails, PARSE_IPv4);
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6))
    {
        bpf_tail_call(ctx, &tails, PARSE_IPv6);
    }

    return XDP_PASS;
}
