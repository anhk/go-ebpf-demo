#include <linux/bpf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

/**
 * using this hook:
 * - libvirt
 */

SEC("cgroup/dev")
int cgroup_device_func(struct bpf_cgroup_dev_ctx *ctx)
{
    // __u64 key = ((__u64)ctx->major << 32) | ctx->minor;
    char fmt[] = "  %d:%d    \n";
    short access = ctx->access_type >> 16;

    switch (ctx->access_type & 0xFFFF) {
    case BPF_DEVCG_DEV_BLOCK:
        fmt[0] = 'b';
        break;
    case BPF_DEVCG_DEV_CHAR:
        fmt[0] = 'c';
        break;
    default:
        fmt[0] = '?';
        break;
    }

    if (access & BPF_DEVCG_ACC_READ)
        fmt[8] = 'r';

    if (access & BPF_DEVCG_ACC_WRITE)
        fmt[9] = 'w';

    if (access & BPF_DEVCG_ACC_MKNOD)
        fmt[10] = 'm';

	bpf_trace_printk(fmt, sizeof(fmt), ctx->major, ctx->minor);

    return SK_PASS;
}