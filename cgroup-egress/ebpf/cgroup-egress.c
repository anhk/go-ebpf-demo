#include <linux/bpf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

SEC("cgroup_skb/ingress")
int cgroup_ingress(struct __sk_buff *skb)
{
    bpf_printk("cgroup-ingress");
    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb)
{
    bpf_printk("cgroup-egress");
    return 1;
}
