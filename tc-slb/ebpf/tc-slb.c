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

unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");

__be32 VIP = 0x2540a8c0; // ==> 192.168.64.37
__u16 VPORT = 0x0F27;    // ==> 9999
__be32 BIP = 0x2640a8c0; // ==> 192.168.64.38
__u16 BPORT = 0x1600;    // ==> 22
__be32 SIP = 0x140a8c0;  // 192.168.64.1

int fixup_ip_checksum(struct __sk_buff *skb)
{
    if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
        return 0;

    // Calculate one's complement sum of IP header except checksum word at
    // offset 24.
    __u64 checksum = 0;
    checksum += load_half(skb, 14);
    checksum += load_word(skb, 16);
    checksum += load_word(skb, 20);
    checksum += load_word(skb, 26);
    checksum += load_word(skb, 30);

    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);

    // Write back correct checksum in the packet.
    __u16 checksum16 = bpf_htons(~checksum);

    bpf_skb_store_bytes(skb, IP_CSUM_OFFSET, &checksum16, 2, 0);

    return 0;
}

int proxy_ipv4(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, __be32 sip, __be32 dip)
{
    if (iph == NULL || tcph == NULL) {
        return TC_ACT_OK;
    }
    bpf_printk("%pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
    // tcph->dest = BPORT;

    bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, iph->daddr, dip, BPF_F_PSEUDO_HDR | sizeof(dip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, iph->daddr, dip, sizeof(dip));

    bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, iph->saddr, sip, BPF_F_PSEUDO_HDR | sizeof(sip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, iph->saddr, sip, sizeof(sip));

    iph->daddr = dip;
    iph->saddr = sip;

    bpf_printk("%pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

    struct bpf_redir_neigh neigh = {
        .nh_family = AF_INET,
        .ipv4_nh = dip,
    };
    return bpf_redirect_neigh(skb->ifindex /*enp0s1*/, &neigh, sizeof(struct bpf_redir_neigh), 0);
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
        return proxy_ipv4(skb, iph, tcph, VIP, BIP);
    } else if (iph->saddr == BIP && tcph->source == VPORT) {
        bpf_printk("==> %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
        return proxy_ipv4(skb, iph, tcph, VIP, SIP);
    } else if (iph->saddr == BIP && tcph->source == BPORT) {
        bpf_printk("=> %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
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