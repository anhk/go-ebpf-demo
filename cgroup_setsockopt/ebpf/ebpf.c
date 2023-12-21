#include <linux/bpf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

#define SOL_CUSTOM			0xdeadbeef

SEC("cgroup/setsockopt")
int k_setsockopt(struct bpf_sockopt *ctx)
{
    if (ctx->level != SOL_CUSTOM) {
        return SK_PASS;
    }
    bpf_printk("--- %x", ctx->level);

    return SK_PASS;
}
