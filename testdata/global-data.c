#include <stddef.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_trace_common.h"
#include <linux/ptrace.h>

bpf_map(my_map, PERF_EVENT_ARRAY, int, char, 2, 0);

static __u64 num1 = 42;
static __u64 num0;
static const __u64 num2 = 24;

SEC("kprobe/__x64_sys_write")
int bpf_prog1(struct pt_regs *ctx)
{
    __u64 c = num0;
    bpf_perf_event_output(ctx, &my_map, 0, &c, 1);
    num0++;

    return 0;
}