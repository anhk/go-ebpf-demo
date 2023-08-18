#include <linux/bpf.h>
#include <linux/if_ether.h> // for struct ethhdr
#include <linux/in.h>       // for IPPROTO_TCP
#include <linux/ip.h>       // for struct iphdr
#include <linux/pkt_cls.h>  // for TC_ACK_OK
#include <linux/string.h>   // for memset
#include <linux/tcp.h>      // for struct tcpdhr

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

#define AF_INET 2
#define IP_CSUM_OFFSET (ETH_HLEN + offsetof(struct iphdr, check))

#define UDP_CSUM_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define TCP_CSUM_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

// unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
// unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");
// unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");

static __be32 VIP = 0x2540a8c0; // ==> 192.168.64.37
static __u16 VPORT = 0x5000;    // ==> 80
static __be32 BIP = 0x6409F40A; // ==> 10.244.9.100
static __be32 SIP = 0x2740A8C0; // ==> 192.168.64.39
static __be32 LIP = 0x2540a8c0; // ==> 192.168.64.37

int proxy_ipv4(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, __be32 sip, __be32 dip)
{
    if (iph == NULL || tcph == NULL) {
        return TC_ACT_OK;
    }
    bpf_printk("[1] %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
    // tcph->dest = BPORT;

    bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, iph->daddr, dip, BPF_F_PSEUDO_HDR | sizeof(dip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, iph->daddr, dip, sizeof(dip));

    bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, iph->saddr, sip, BPF_F_PSEUDO_HDR | sizeof(sip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, iph->saddr, sip, sizeof(sip));

    iph->daddr = dip;
    iph->saddr = sip;

    bpf_printk("[2] %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

    struct bpf_redir_neigh neigh = {
        .nh_family = AF_INET,
        .ipv4_nh = dip,
    };

//     if (tcph->source == VPORT) { // 发往其他节点
//          bpf_printk("to %d",skb->ifindex);
    //    return bpf_redirect_neigh(skb->ifindex /*enp0s1*/, &neigh, sizeof(struct bpf_redir_neigh), 0);
//   }
    //    return bpf_redirect_neigh(4/*enp0s1*/, &neigh, sizeof(struct bpf_redir_neigh), 0);

//   bpf_printk("to 4");
        // return bpf_redirect(4/*flannel.1*/, 0);

    return TC_ACT_OK; // 发往本节点，可以是IPVLAN或 VEth pair
}

int tc_process_ipv4(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (iph->daddr == VIP && tcph->dest == VPORT) {
        return proxy_ipv4(skb, iph, tcph, LIP, BIP);
    } else if (iph->saddr == BIP && tcph->source == VPORT) {
        bpf_printk("==> %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
        return proxy_ipv4(skb, iph, tcph, VIP, SIP);
    }

    // bpf_printk("%x:%x -> %x:%x", iph->saddr, tcph->source, iph->daddr, tcph->dest);

    return TC_ACT_OK;
}

SEC("classifier/ingress")
int tc_process(struct __sk_buff *skb)
{
    if (skb->protocol == 0x0008 /*IPv4*/) {
        return tc_process_ipv4(skb);
    } else if (skb->protocol != 0xDD64 /*IPv6*/) {
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb)
{
    if (skb->protocol == 0x0008 /*IPv4*/) {
        return tc_process_ipv4(skb);
    } else if (skb->protocol != 0xDD64 /*IPv6*/) {
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}