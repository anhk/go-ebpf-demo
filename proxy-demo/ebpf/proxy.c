#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __uint(pinning, 1);
    __type(value, __u32);
} sock_map SEC(".maps");

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_TCP) {
        return SK_PASS;
    }
    if (ctx->user_port != bpf_ntohs(80)) {
        return SK_PASS;
    }
    if (ctx->user_ip4 != 0x3540a8c0) { // 192.168.64.53
        return SK_PASS;
    }
    bpf_sk_storage_get(&sock_map, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    return SK_PASS;
}

#define ensure_header(skb, off, typ)                      \
    ({                                                    \
        __s32 __l = (__s32)off, __s = (__s32)sizeof(typ); \
        if (__l < 0 || __s <= 0 || __l + __s > 0xFFFF) {  \
            return SK_PASS;                               \
        }                                                 \
        void *data = (void *)(long)skb->data + __l;       \
        void *data_end = (void *)(long)skb->data_end;     \
        if (data > data_end || data + __s > data_end) {   \
            return SK_PASS;                               \
        }                                                 \
        (typ *)(data);                                    \
    })

SEC("cgroup_skb/egress")
int sock_egress(struct __sk_buff *skb)
{
    if (skb->sk == NULL) {
        return SK_PASS;
    }
    if (skb->protocol != bpf_ntohs(ETH_P_IP)){
          return SK_PASS;
    }

    void *sk = skb->sk;
    void *ret = bpf_sk_storage_get(&sock_map, sk, 0, 0);
    if (ret == NULL) {
        return SK_PASS;
    }

    // 直接是三层头+四层头
    struct iphdr *iph = ensure_header(skb, 0, struct iphdr);

    // skb->mark = 0x0C00;
    // bpf_clone_redirect(skb, skb->ifindex, 0);

    bpf_printk("found, ifindex: %d, ingress_ifindex: %d", skb->ifindex, skb->ingress_ifindex);
    bpf_printk(" -- %pI4 -> %pI4", &iph->saddr, &iph->daddr);
    return SK_PASS;
}
