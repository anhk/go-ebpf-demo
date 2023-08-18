#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "GPL";
/*************************************************************************************/
#define ETH_P_IP 0x0800

/*************************************************************************************/
static __be32 DSTIP = 0x2540a8c0; // ==> 192.168.64.37
static __u16 DSTPORT = 0x5000;    // ==> 80
// static __u16 DSTPORT = 0x2B19;    // ==> 6443
static __be32 SRCIP = 0x2740A8C0; // ==> 192.168.64.39

/*************************************************************************************/
static inline int do_trace(struct pt_regs *ctx, struct sk_buff *skb, const char *func_name)
{
    void *head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    network_header = (network_header == 0 ? mac_header + 14 : network_header);

    struct ethhdr *eth = head + mac_header;
    __u8 eth_type = BPF_CORE_READ(eth, h_proto);
    if (eth_type != bpf_htons(ETH_P_IP)) { // not IPv4
        return 0;
    }
    struct iphdr *iph = head + network_header;

    __be32 saddr = BPF_CORE_READ(iph, saddr);
    __be32 daddr = BPF_CORE_READ(iph, daddr);

    __u8 b; // IP头部长度
    bpf_probe_read(&b, 1, iph);
    b = (b & 0x0f) * 4;

    struct tcphdr *tcph = head + network_header + b;

    __u16 sport = BPF_CORE_READ(tcph, source);
    __u16 dport = BPF_CORE_READ(tcph, dest);

    if (daddr == DSTIP && dport == DSTPORT) {
        bpf_printk("%s ==> %pI4:%d -> %pI4:%d", func_name, &saddr, bpf_ntohs(sport), &daddr, bpf_ntohs(dport));
    }

    return 0;
}

/*************************************************************************************/
SEC("kprobe/__netif_receive_skb")
int k__netif_receive_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "__netif_receive_skb");
}
