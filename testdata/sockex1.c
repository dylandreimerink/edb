#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long);
    __uint(max_entries, 256);
} my_map SEC(".maps");

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
    __u8 index = (__u8)load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    long *value;

    void *data = (void *)(long)skb->data;
    __u8 *protocolPtr = data + ETH_HLEN + offsetof(struct iphdr, protocol);

    if (index != *protocolPtr)
    {
        // Legacy access and direct packet access return different results.
        return 0;
    }

    if (skb->pkt_type == PACKET_OUTGOING)
        return 0;

    value = bpf_map_lookup_elem(&my_map, &index);
    if (value)
        *value += skb->len;

    return 0;
}
char _license[] SEC("license") = "GPL";