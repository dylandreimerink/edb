#include <stddef.h>
#include <linux/bpf.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

// This example program will loop over all number sequences in `array_of_number_sequences` and compute the sum.
// Which will be written back into `results`

#define NUM_SEQ 4
#define SEQ_LEN 8

bpf_map(array_of_number_sequences, ARRAY_OF_MAPS, __u32, __u32, NUM_SEQ, 0);

bpf_map(results, ARRAY, __u32, __u32, NUM_SEQ, 0);

// https://en.wikipedia.org/wiki/Fibonacci_number
bpf_map(fibonacci_numbers, ARRAY, __u32, __u32, SEQ_LEN, 0);

// https://en.wikipedia.org/wiki/Lucky_number
bpf_map(lucky_numbers, ARRAY, __u32, __u32, SEQ_LEN, 0);

// https://en.wikipedia.org/wiki/Semiprime
bpf_map(semi_prime_powers, ARRAY, __u32, __u32, SEQ_LEN, 0);

// https://en.wikipedia.org/wiki/Untouchable_number
bpf_map(untouchable_numbers, ARRAY, __u32, __u32, SEQ_LEN, 0);

SEC("xdp")
int sum_sequences()
{
    for (__u32 i = 0; i < NUM_SEQ; i++)
    {
        struct bpf_map *seqMap = bpf_map_lookup_elem(&array_of_number_sequences, &i);
        if (!seqMap)
        {
            return XDP_ABORTED;
        }

        __u32 *seqResult = bpf_map_lookup_elem(&results, &i);
        if (!seqResult)
        {
            return XDP_ABORTED;
        }
        *seqResult = 0;

        for (__u32 j = 0; j < SEQ_LEN; j++)
        {
            __u32 *seqNum = bpf_map_lookup_elem(seqMap, &j);
            if (!seqNum)
            {
                return XDP_ABORTED;
            }

            *seqResult += *seqNum;
        }
    }

    return XDP_PASS;
}