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

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

/*
 * bpf_map_lookup_elem
 *
 * 	Perform a lookup in *map* for an entry associated to *key*.
 *
 * Returns
 * 	Map value associated to *key*, or **NULL** if no entry was
 * 	found.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

/*
 * bpf_map_update_elem
 *
 * 	Add or update the value of the entry associated to *key* in
 * 	*map* with *value*. *flags* is one of:
 *
 * 	**BPF_NOEXIST**
 * 		The entry for *key* must not exist in the map.
 * 	**BPF_EXIST**
 * 		The entry for *key* must already exist in the map.
 * 	**BPF_ANY**
 * 		No condition on the existence of the entry for *key*.
 *
 * 	Flag value **BPF_NOEXIST** cannot be used for maps of types
 * 	**BPF_MAP_TYPE_ARRAY** or **BPF_MAP_TYPE_PERCPU_ARRAY**  (all
 * 	elements always exist), the helper would return an error.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;


struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct traffic_stats {
	__u64 pkts;
	__u64 bytes;
};

// Stats on packets keyed by protocol number
struct bpf_map_def SEC("maps") ip_proto_stats = {
	.type        = BPF_MAP_TYPE_LRU_PERCPU_HASH,
	.key_size    = sizeof(__u8),
	.value_size  = sizeof(struct traffic_stats),
	.max_entries = 16, // stats on top 16 protocol seem more than enough
	.map_flags 	 = BPF_F_NO_COMMON_LRU,
};

// Stats on udp packets keyed by dest port
struct bpf_map_def SEC("maps") udp_stats = {
	.type        = BPF_MAP_TYPE_LRU_PERCPU_HASH,
	.key_size    = sizeof(__u16),
	.value_size  = sizeof(struct traffic_stats),
	.max_entries = 128, // top 128 udp ports seems good enough
	.map_flags   = BPF_F_NO_COMMON_LRU,
};

// Stats on tcp packets keyed by dest port
struct bpf_map_def SEC("maps") tcp_stats = {
	.type        = BPF_MAP_TYPE_LRU_PERCPU_HASH,
	.key_size    = sizeof(__u16),
	.value_size  = sizeof(struct traffic_stats),
	.max_entries = 128, // top 128 tcp ports seems good enough
	.map_flags   = BPF_F_NO_COMMON_LRU,
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __noinline void inc_ip_proto(
	__u8 proto,
	__u64 framesize
) {
	struct traffic_stats* stats_ptr = bpf_map_lookup_elem(&ip_proto_stats, &proto);
	if( stats_ptr == NULL ) {
		// Make a new stats object
		struct traffic_stats stats = {
            .pkts = 1,
            .bytes = framesize,
        };
		bpf_map_update_elem(&ip_proto_stats, &proto, &stats, BPF_ANY);
	} else {
		stats_ptr->pkts++;
        stats_ptr->bytes += framesize;
	}
}

static __noinline void inc_tcp(
	struct tcphdr* tcphdr,
	__u64 framesize
){
	__le16 le_dest = bpf_ntohs(tcphdr->dest);
	// Get existing stats
	struct traffic_stats* stats_ptr = bpf_map_lookup_elem(&tcp_stats, &le_dest);
	if( stats_ptr == NULL ) {
		// Make a new stats object
		struct traffic_stats stats = {
            .pkts = 1,
            .bytes = framesize,
        };
		bpf_map_update_elem(&tcp_stats, &le_dest, &stats, BPF_ANY);
	} else {
        stats_ptr->pkts++;
        stats_ptr->bytes += framesize;
	}
}

static __noinline void inc_udp(
	struct udphdr* udphdr,
	__u64 framesize
){
	__le16 le_dest = bpf_ntohs(udphdr->dest);
	// Get existing stats
	struct traffic_stats* stats_ptr = bpf_map_lookup_elem(&udp_stats, &le_dest);
	if( stats_ptr == NULL ) {
		// Make a new stats object
		struct traffic_stats stats = {
            .pkts = 1,
            .bytes = framesize,
        };

		bpf_map_update_elem(&udp_stats, &le_dest, &stats, BPF_ANY);
	} else {
		stats_ptr->pkts++;
        stats_ptr->bytes += framesize;
	}
}

static __noinline void handle_ipv4(void* data, void* data_end, __u64 nh_off) {
	struct iphdr* iph = data + nh_off;
	nh_off += sizeof(struct iphdr);
	__u64 framesize = data_end - data;

	// Drop packets which don't have enough data to fit the IPv4 header
	if( data + nh_off > data_end ){
		return;
	}

	__u8 ipproto = iph->protocol;

    inc_ip_proto(ipproto, framesize);

	if( ipproto == IPPROTO_UDP ){
        struct udphdr* udphdr = data + nh_off;
        nh_off += sizeof(struct udphdr);
        
        // If there is not enough data to parse a UDP header, drop the packet
        if( data + nh_off > data_end ) {
            return;
        }

        inc_udp(udphdr, framesize);
    }

    if( ipproto == IPPROTO_TCP ){
        struct tcphdr* tcphdr = data + nh_off;
        nh_off += sizeof(struct tcphdr);

        
        // If there is not enough data to parse a UDP header, drop the packet
        if( data + nh_off > data_end ) {
            return;
        }

        inc_tcp(tcphdr, framesize);
    }
}

static __noinline void handle_ipv6(void* data, void* data_end, __u64 nh_off) {
	struct ipv6hdr* ip6h = data + nh_off;
	nh_off += sizeof(struct ipv6hdr);
	__u64 framesize = data_end - data;

	// Drop packets which don't have enough data to fit the IPv4 header
	if( data + nh_off > data_end ){
		return;
	}

	__u8 ipproto = ip6h->nexthdr;

	inc_ip_proto(ipproto, framesize);

    if( ipproto == IPPROTO_UDP ){
        struct udphdr* udphdr = data + nh_off;
        nh_off += sizeof(struct udphdr);
        
        // If there is not enough data to parse a UDP header, drop the packet
        if( data + nh_off > data_end ) {
            return;
        }

        inc_udp(udphdr, framesize);
    }

    if( ipproto == IPPROTO_TCP ){
        struct tcphdr* tcphdr = data + nh_off;
        nh_off += sizeof(struct tcphdr);
        
        // If there is not enough data to parse a TCP header, drop the packet
        if( data + nh_off > data_end ) {
            return;
        }

        inc_tcp(tcphdr, framesize);
    }
}

SEC("xdp/proto_stats")
int firewall_prog(struct xdp_md *ctx)
{
	void* data_end = (void *)(long)ctx->data_end;
	void* data = (void *)(long)ctx->data;

	// Offset to the next header
	__u64 nh_off = sizeof(struct ethhdr);

	// If we don't even have enough data to a ethernet frame header, drop the message
	if( data + nh_off > data_end ){
		return XDP_DROP;
	}

	struct ethhdr* eth = data;
	__be16 h_proto = eth->h_proto;

	// If the ethernet packet contains a IEEE 802.1Q or 802.1AD VLAN header
	if( h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD) ){
		struct vlan_hdr* vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		
		// Drop packets which don't have enough data to fit the VLAN header
		if( data + nh_off > data_end ){
			return XDP_DROP;
		}

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if( h_proto == bpf_htons(ETH_P_IP) ){
		handle_ipv4(data, data_end, nh_off);
	} else if( h_proto == bpf_htons(ETH_P_IPV6) ){
		handle_ipv6(data, data_end, nh_off);
	}
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";