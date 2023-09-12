#include "s.h"

SEC("cgroup/connect4")
int sock_connect444(struct bpf_sock_addr* ctx)
{
    bpf_printk("******");
    return 1;
}

