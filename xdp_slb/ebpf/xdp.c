#include <linux/bpf.h>
#include <linux/if_ether.h> // for struct ethhdr
#include <linux/in.h>       // for IPPROTO_TCP
#include <linux/ip.h>       // for struct iphdr
#include <linux/tcp.h>      // for struct tcpdhr
#include "bpf_endian.h"
#include "bpf_helpers.h"

#define MAX_VIP_ENTRIES 4096
#define MAX_BACKEND_ENTRIES 4096

struct slb_key {
    __u32 vip;
    __u16 port;
    __u16 _pad1;
    __u32 slot;
    __u32 _pad2;
} __attribute__((__packed__));

struct slb_value {
    __u32 count;
    __u32 rip;
    __u16 port;
    __u16 _pad1;
    __u32 _pad2;
} __attribute__((__packed__));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct slb_key);
    __type(value, struct slb_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, MAX_VIP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} slb_map SEC(".maps");

SEC("xdp")
int xdp_slb(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int sz = data_end - data;

    // bpf_printk("iface[%d] packet size: %d", ctx->ingress_ifindex, sz);
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return XDP_PASS;
    }

    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    struct slb_key key = {
        .vip = iph->daddr,
        .port = tcph->dest,
        .slot = 0,
    };

    struct slb_value *value;
    if ((value = bpf_map_lookup_elem(&slb_map, &key)) == NULL) {
        return XDP_PASS;
    }

    // SLB
    key.slot = bpf_get_prandom_u32() % value->count + 1;
    bpf_printk("slot: %d", key.slot);

    if ((value = bpf_map_lookup_elem(&slb_map, &key)) == NULL) {
        return XDP_PASS;
    }

    bpf_printk("got backend: count: %d, rip: %pI4, port: %d", value->count, value->rip, value->port);
    bpf_printk("backend pad: %x %x", value->_pad1, value->_pad2);
    return XDP_DROP;
}

char __license[] SEC("license") = "GPL";