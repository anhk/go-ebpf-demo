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
#define IP_CSUM_OFFSET (sizeof(struct ethhdr) + offsetof(struct iphdr, check))
#define UDP_CSUM_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define TCP_CSUM_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

__be32 VIP = 0x2540a8c0; // ==> 192.168.64.37
__u16 VPORT = 0x0F27;    // ==> 9999
__be32 BIP = 0x2640a8c0; // ==> 192.168.64.38
__u16 BPORT = 0x1600;    // ==> 22

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
        bpf_printk("%pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

        // __s64 sum = 0;
        // __be32 old_ip = iph->daddr;
        // __be32 new_ip = BIP;
        // sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, 0);
        // bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, iph->daddr , BIP, sizeof(BIP));
        iph->daddr = BIP;
        // bpf_l4_csum_replace(skb, IP_CSUM_OFFSET, 0, sum, BPF_F_PSEUDO_HDR);
        // tcph->dest = BPORT;

        // old_ip = iph->saddr;
        // new_ip = VIP;
        // sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, 0);
        iph->saddr = VIP;
        // bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, sum, 0);
        // bpf_l4_csum_replace(skb, IP_CSUM_OFFSET, 0, sum, BPF_F_PSEUDO_HDR);
        // bpf_l4_csum_replace(skb,TCP_CSUM_OFF, );
        bpf_printk("%pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
        // bpf_skc_lookup_tcp();

        // bpf_set_hash_invalid(skb);
        // bpf_get_hash_recalc(skb);

        struct bpf_redir_neigh neigh = {
            .nh_family = AF_INET,
            .ipv4_nh = BIP,
        };
        // memset(&neigh, 0, sizeof(struct bpf_redir_neigh));
        return bpf_redirect_neigh(skb->ifindex /*enp0s1*/, &neigh, sizeof(struct bpf_redir_neigh), 0);
    } else if (iph->saddr == BIP && tcph->source == VPORT) {
        bpf_printk("=> %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
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