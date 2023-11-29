#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct value {
    int count;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __uint(pinning, 1);
    __type(value, struct value);
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

static int sock_process(struct __sk_buff *skb)
{
    if (skb->sk == NULL) {
        return SK_PASS;
    }
    if (skb->protocol != bpf_ntohs(ETH_P_IP)) {
        return SK_PASS;
    }

    void *sk = skb->sk;
    struct value *val = bpf_sk_storage_get(&sock_map, sk, 0, 0);
    if (val == NULL) {
        return SK_PASS;
    }
    val->count++;
    bpf_printk("storage: %d", val->count);

    // 直接是三层头+四层头
    struct iphdr *iph = ensure_header(skb, 0, struct iphdr);
    if (iph->protocol != IPPROTO_TCP) {
        return SK_PASS;
    }

    int len = iph->ihl << 2;

    // skb->mark = 0x0C00;
    // bpf_clone_redirect(skb, skb->ifindex, 0);

    bpf_printk("found, ifindex: %d, ingress_ifindex: %d", skb->ifindex, skb->ingress_ifindex);
    bpf_printk(" -- %pI4 -> %pI4 iph: %d, len: %d", &iph->saddr, &iph->daddr, len, bpf_ntohs(iph->tot_len));

    struct tcphdr *tcph = ensure_header(skb, len, struct tcphdr);
    // bpf_printk("[%d-%d]", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
    bpf_printk("syn:%d, psh:%d, ack:%d, fin:%d, rst:%d", tcph->syn, tcph->psh, tcph->ack, tcph->fin, tcph->rst);

    if (val->count == 3) {
        bpf_printk("[!!!] skb->len: %d", skb->len);
        char data[] = "PROXY TCP4 192.168.64.1 192.168.64.53 33333 80\r\n";
        int newlen = skb->len + sizeof(data) - 1;
        bpf_printk("[!!!] newlen: %d", newlen);
        bpf_printk("[!!!] data: %x, data_end: %x, diff: %d", skb->data, skb->data_end, skb->data_end - skb->data);
        // int ret = bpf_skb_change_tail(skb, newlen, 0);
        // bpf_printk("ret = %d", ret);
    }

    return SK_PASS;
}

SEC("cgroup_skb/ingress")
int sock_ingress(struct __sk_buff *skb)
{
    return sock_process(skb);
}

SEC("cgroup_skb/egress")
int sock_egress(struct __sk_buff *skb)
{
    return sock_process(skb);
}
