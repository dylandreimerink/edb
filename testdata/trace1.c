#include <stddef.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_trace_common.h"
#include <linux/ptrace.h>

struct S
{
    __u64 pid;
    __u64 cookie;
};

bpf_map(my_map, PERF_EVENT_ARRAY, int, struct S, 2, 0);

SEC("kprobe/__x64_sys_write")
int bpf_prog1(struct pt_regs *ctx)
{
    struct S data;

    data.pid = bpf_get_current_pid_tgid();
    data.cookie = 0x12345678;

    bpf_perf_event_output(ctx, &my_map, 0, &data, sizeof(data));

    return 0;
}