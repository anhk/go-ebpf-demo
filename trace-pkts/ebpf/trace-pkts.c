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

// static __be32 VIP = 0x2540a8c0; // ==> 192.168.64.37
// static __u16 VPORT = 0x5000;    // ==> 80
static __be32 BACKIP = 0x6409F40A; // ==> 10.244.9.100
// static __be32 SIP = 0x2740A8C0; // ==> 192.168.64.39
// static __be32 LIP = 0x2540a8c0; // ==> 192.168.64.37
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
    __be32 seq = BPF_CORE_READ(tcph,seq); 

    if ((daddr == BACKIP || daddr == DSTIP) && dport == DSTPORT) {
        bpf_printk("%s ==>[%u] %pI4:%d -> %pI4:%d", func_name, seq, &saddr, bpf_ntohs(sport), &daddr, bpf_ntohs(dport));
    }
    return 0;
}

/*************************************************************************************/
SEC("kprobe/__netif_receive_skb") // 没命中
int k__netif_receive_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "__netif_receive_skb");
}

SEC("kprobe/__netif_receive_skb_one_core") // 没命中
int k__netif_receive_skb_one_core(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "__netif_receive_skb_one_core");
}

SEC("kprobe/netif_receive_skb_core") // 没命中
int k_netif_receive_skb_core(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "netif_receive_skb_core");
}

SEC("tracepoint/net/netif_receive_skb")
int t_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    return do_trace(NULL, skb, "netif_receive_skb");
}

SEC("kprobe/ip_rcv_core")
int k_ip_rcv_core(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "ip_rcv_core");
}

SEC("kprobe/ip_rcv_finish")
int k_ip_rcv_finish(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "ip_rcv_finish");
}

SEC("kprobe/ip_forward")
int k_ip_forward(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return do_trace(ctx, skb, "ip_forward");
}

SEC("kprobe/ip_forward_finish")
int k_ip_forward_finish(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    return do_trace(ctx, skb, "ip_forward_finish");
}

SEC("kprobe/tcp_v4_do_rcv")
int k_tcp_v4_do_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return do_trace(ctx, skb, "tcp_v4_do_rcv");
}

SEC("kprobe/tcp_filter")
int k_tcp_filter(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return do_trace(ctx, skb, "tcp_filter");
}
