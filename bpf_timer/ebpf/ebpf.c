#include <linux/bpf.h>
#include <linux/time.h> // for CLOCK_REALTIME

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct map_elem {
    int counter;
    struct bpf_timer timer;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, int);
    __type(value, struct map_elem);
} hmap SEC(".maps");

static int timer_cb(void *map, int *key, struct map_elem *val)
{
    bpf_printk("time_cb");
    return 0;
}

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != 2) {
        return SK_PASS;
    }

    __u32 ip = ctx->user_ip4;
    __u16 port = ctx->user_port;
    bpf_printk("connect4: %pI4:%d", &ip, bpf_ntohs(port));

    int key = 0;
    struct map_elem *elem = bpf_map_lookup_elem(&hmap, &key);
    if (elem != NULL) {
        bpf_printk("set timer.");
        bpf_timer_init(&elem->timer, &hmap, CLOCK_REALTIME);
        bpf_timer_set_callback(&elem->timer, timer_cb);
        bpf_timer_start(&elem->timer, /* 1 usec */ 1000, 0);
        bpf_timer_start(&elem->timer, /* 1 msec */ 1000 * 1000, 0);
        bpf_timer_start(&elem->timer, /* 1  sec */ 1000 * 1000 * 1000, 0);
    } else {
        bpf_printk("add elem");
        struct map_elem elem = {};
        bpf_map_update_elem(&hmap, &key, &elem, BPF_ANY);
    }

    return SK_PASS;
}