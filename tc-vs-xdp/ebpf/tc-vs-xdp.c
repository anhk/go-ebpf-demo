
#include <linux/bpf.h>     // for XDP_PASS
#include <linux/pkt_cls.h> // for TC_ACK_OK

#include "bpf_endian.h"
#include "bpf_helpers.h"

SEC("xdp")
int xdp_process(struct xdp_md *ctx)
{
    bpf_printk("xdp_process");
    return XDP_PASS;
}

SEC("tc")
int tc_process(struct __sk_buff *skb)
{
    bpf_printk("tc_process");
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";