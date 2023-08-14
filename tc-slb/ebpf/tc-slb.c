#include <linux/bpf.h>
#include <linux/pkt_cls.h> // for TC_ACK_OK

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";


SEC("classifier/ingress")
int tc_process(struct __sk_buff *skb)
{
    bpf_printk("tc_process");
    return TC_ACT_OK;
}