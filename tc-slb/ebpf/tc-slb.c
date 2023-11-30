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
#define MAX_CONN_ENTRIES 65536
#define MAGIC_MASK 0x0F00
#define INGRESS 1
#define EGRESS 2

struct tuple_t {
    __be32 saddr;  // 192.168.64.1
    __be32 daddr;  // 192.168.64.37
    __be16 sport;  // 30001
    __be16 dport;  // 80
    __u8 protocol; // TCP
    __u8 pad;      //
    __be16 pad2;   //
};

struct entry_t {
    __be32 addr; // 192.168.64.1
    __be16 port; // 30000
    __be16 pad1;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct tuple_t);
    __type(value, struct entry_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, MAX_CONN_ENTRIES);
    // __uint(map_flags, BPF_F_NO_PREALLOC);
    // --- htab_map_alloc_check 函数中检查，BPF_MAP_TYPE_LRU_HASH类型的Map不能有BPF_F_NO_PREALLOC标记
} conn_map SEC(".maps");

static __be32 VIP = 0x3440a8c0; // ==> 192.168.64.52
static __u16 VPORT = 0x5000;    // ==> 80
static __be32 BIP = 0x3540a8c0; // ==> 192.168.64.53
static __be32 LIP = 0x3440a8c0; // ==> 192.168.64.52

// sch_handle_ingress
// tc_cls_act_is_valid_access, skb->family到skb->localport不可访问

int try_do_dnat(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, struct entry_t *value)
{
    if (skb == NULL || iph == NULL || tcph == NULL || value == NULL) {
        return TC_ACT_OK;
    }

    bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, iph->daddr, value->addr, BPF_F_PSEUDO_HDR | sizeof(value->addr));
    bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, tcph->dest, value->port, sizeof(value->port));
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, iph->daddr, value->addr, sizeof(value->addr));

    bpf_printk("[DNAT-F] %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
    iph->daddr = value->addr;
    tcph->dest = value->port;
    bpf_printk("[DNAT-T] %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

    return TC_ACT_OK;
}

int try_do_snat(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, struct entry_t *value)
{
    if (skb == NULL || iph == NULL || tcph == NULL || value == NULL) {
        return TC_ACT_OK;
    }

    bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, iph->saddr, value->addr, BPF_F_PSEUDO_HDR | sizeof(value->addr));
    bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, tcph->source, value->port, sizeof(value->port));
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, iph->saddr, value->addr, sizeof(value->addr));

    bpf_printk("[SNAT-F] %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));
    iph->saddr = value->addr;
    tcph->source = value->port;
    bpf_printk("[SNAT-T] %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

    return TC_ACT_OK;
}

// ---------------  key  ---------------------  value ------------------
// -> DNAT: 192.168.64.39->192.168.64.37 ==> 192.168.64.39->10.244.0.9
// -> SNAT: 192.168.64.39->10.244.0.9 ==> 192.168.64.37->10.244.0.9
// => DNAT: 10.244.0.9->192.168.64.37 => 10.244.0.9->192.168.64.39
// => SNAT: 10.244.0.9->192.168.64.39 => 192.168.64.37->192.168.64.39

int proxy_ipv4_ingress(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, struct tuple_t *key)
{
    if (skb == NULL || iph == NULL || tcph == NULL || key == NULL) {
        return TC_ACT_OK;
    }
    if (iph->daddr != VIP || tcph->dest != VPORT) {
        return TC_ACT_OK;
    }
    // TODO: 新连接，需要检查SYN
    bpf_printk("[N-I] %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

    // -> DNAT: 192.168.64.39->192.168.64.37 ==> 192.168.64.39->10.244.0.9
    struct entry_t value = {
        .addr = BIP,
        .port = VPORT,
    };

    skb->mark |= MAGIC_MASK;
    bpf_map_update_elem(&conn_map, key, &value, BPF_NOEXIST);

    // => SNAT: 10.244.0.9->192.168.64.39 => 192.168.64.37->192.168.64.39
    struct tuple_t nkey = {
        .saddr = value.addr,
        .sport = value.port,
        .daddr = iph->saddr,
        .dport = tcph->source,
        .protocol = iph->protocol,
    };

    struct entry_t nvalue = {
        .addr = VIP,
        .port = VPORT,
    };
    bpf_map_update_elem(&conn_map, &nkey, &nvalue, BPF_NOEXIST);
    return try_do_dnat(skb, iph, tcph, &value);
}

int proxy_ipv4_egress(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, struct tuple_t *key)
{
    if (skb == NULL || iph == NULL || tcph == NULL || key == NULL) {
        return TC_ACT_OK;
    }
    if (!(skb->mark & MAGIC_MASK)) {
        return TC_ACT_OK;
    }

    bpf_printk("[N-E] %pI4:%d -> %pI4:%d", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

    // -> SNAT: 192.168.64.39->10.244.0.9 ==> 192.168.64.37->10.244.0.9
    struct entry_t value = {
        .addr = LIP,
        .port = tcph->source,
    };

    bpf_map_update_elem(&conn_map, key, &value, BPF_NOEXIST);

    // => DNAT: 10.244.0.9->192.168.64.37 => 10.244.0.9->192.168.64.39
    struct tuple_t nkey = {
        .daddr = value.addr,
        .dport = value.port,
        .saddr = iph->daddr,
        .sport = tcph->dest,
        .protocol = iph->protocol,
    };

    struct entry_t nvalue = {
        .addr = iph->saddr,
        .port = tcph->source,
    };
    bpf_map_update_elem(&conn_map, &nkey, &nvalue, BPF_NOEXIST);

    return try_do_snat(skb, iph, tcph, &value);
}

int proxy_ipv4(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, struct tuple_t *key, int direction)
{
    if (skb == NULL || iph == NULL || tcph == NULL || key == NULL) {
        return TC_ACT_OK;
    }

    if (direction == INGRESS) { // INGRESS
        return proxy_ipv4_ingress(skb, iph, tcph, key);
    } else { // EGRESS
        return proxy_ipv4_egress(skb, iph, tcph, key);
    }
}

int tc_process_ipv4(struct __sk_buff *skb, int direction)
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

    struct tuple_t key = {
        .daddr = iph->daddr,
        .dport = tcph->dest,
        .saddr = iph->saddr,
        .sport = tcph->source,
        .protocol = iph->protocol,
    };

    struct entry_t *value = (struct entry_t *)bpf_map_lookup_elem(&conn_map, &key);
    if (value == NULL) {
        return proxy_ipv4(skb, iph, tcph, &key, direction);
    }

    int ok = (direction == INGRESS) ? try_do_dnat(skb, iph, tcph, value) : try_do_snat(skb, iph, tcph, value);
    if (tcph->fin || tcph->rst) { // 删除连接: FIXME，要处理四次挥手，加 TIME_WAIT ？
        // bpf_map_delete_elem(&conn_map, &key);
    }
    return ok;
}

SEC("classifier/ingress")
int tc_process(struct __sk_buff *skb)
{
    if (skb->protocol == 0x0008 /*IPv4*/) {
        return tc_process_ipv4(skb, INGRESS);
    } else if (skb->protocol == 0xDD64 /*IPv6*/) { // 暂不处理
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb)
{
    if (skb->protocol == 0x0008 /*IPv4*/) {
        return tc_process_ipv4(skb, EGRESS);
    } else if (skb->protocol == 0xDD64 /*IPv6*/) { // 暂不处理
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}