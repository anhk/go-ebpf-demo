#include <linux/bpf.h>
#include <linux/if_ether.h> // for struct ethhdr
#include <linux/in.h>       // for IPPROTO_TCP
#include <linux/ip.h>       // for struct iphdr
#include <linux/string.h>   // for memset
#include <linux/tcp.h>      // for struct tcpdhr
#include "bpf_endian.h"
#include "bpf_helpers.h"

#define MAX_VIP_ENTRIES 4096
#define MAX_BACKEND_ENTRIES 4096

#define AF_INET 2

struct slb_key {
    __u32 vip;
    __u16 port;
    __u16 _pad1;
    __u32 slot;
    __u32 _pad2;
};

struct slb_value {
    __u32 count;
    __u32 rip;
    __u16 port;
    __u16 _pad1;
    __u32 _pad2;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct slb_key);
    __type(value, struct slb_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, MAX_VIP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} slb_map SEC(".maps");

static int fib_redirect(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph, __u32 lip, __u32 rip)
{
    // FIXME: field XdpSlb: program xdp_slb: load program: permission denied: invalid indirect read from stack R2 off
    // -64+13 size 64 (125 line(s) omitted)

    struct bpf_fib_lookup fib_params;
    memset(&fib_params, 0, sizeof(fib_params));

    fib_params.family = AF_INET;
    fib_params.tos = iph->tos;
    fib_params.l4_protocol = iph->protocol;
    fib_params.tot_len = bpf_ntohs(iph->tot_len);
    fib_params.ipv4_src = lip;
    fib_params.ipv4_dst = rip;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    bpf_printk("bpf_fib_lookup return %d", rc);
    bpf_printk(" - src: %02x:%02x:%02x:%02x:%02x:%02x, dst: %02x:%02x:%02x:%02x:%02x:%02x", fib_params.smac[0],
               fib_params.smac[1], fib_params.smac[2], fib_params.smac[3], fib_params.smac[4], fib_params.smac[5],
               fib_params.dmac[0], fib_params.dmac[1], fib_params.dmac[2], fib_params.dmac[3], fib_params.dmac[4],
               fib_params.dmac[5]);

    switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
    memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
    memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
    return XDP_TX;
    case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */
        return XDP_DROP;
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
    default:
        break;
    }

    return XDP_DROP;
}

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
    if ((value = bpf_map_lookup_elem(&slb_map, &key)) == NULL) {
        return XDP_PASS;
    }
    bpf_printk("got backend: slot: %d, rip: %pI4, port: %d", key.slot, &(value->rip), bpf_ntohs(value->port));

    return fib_redirect(ctx, eth, iph, iph->daddr, value->rip);
}

char __license[] SEC("license") = "GPL";