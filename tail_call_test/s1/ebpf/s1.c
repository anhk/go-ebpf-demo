#include "s.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} tj_map SEC(".maps");

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
    bpf_printk("-----");
    bpf_tail_call(ctx, &tj_map, 1);
    bpf_printk("+++++");
    return 1;
}