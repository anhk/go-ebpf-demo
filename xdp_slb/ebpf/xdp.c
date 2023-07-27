#include <linux/bpf.h>
#include <linux/if_ether.h> // for struct ethhdr
#include "bpf_helpers.h"

SEC("xdp")
int xdp_slb(struct xdp_md *ctx)
{
    // bpf_printk("iface: %d", ctx->ingress_ifindex);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int sz = data_end - data;

    bpf_printk("iface[%d] packet size: %d", ctx->ingress_ifindex, sz);
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";