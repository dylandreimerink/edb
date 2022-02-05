#include <stddef.h>
#include <linux/bpf.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

// This example reads all values from the stack and sums them, then pushes back the restult.

bpf_map(num_stack, STACK, __u32, __u32, 16, 0);

SEC("xdp")
int sum_stack()
{
    __u32 sum = 0;
    while (1)
    {
        __u32 *val;
        // This peek is useless, just here to test that the helper works
        long ret = bpf_map_peek_elem(&num_stack, &val);
        if (ret != 0)
        {
            break;
        }

        ret = bpf_map_pop_elem(&num_stack, &val);
        if (ret != 0)
        {
            return XDP_ABORTED;
        }

        sum += *val;
    }

    long ret = bpf_map_push_elem(&num_stack, &sum, 0);
    if (ret != 0)
    {
        return XDP_ABORTED;
    }

    return XDP_PASS;
}