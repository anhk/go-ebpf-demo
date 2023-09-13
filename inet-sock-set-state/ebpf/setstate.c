#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct something {
    int a, b, c, d;
};

// struct {
//     __uint(type, BPF_MAP_TYPE_SK_STORAGE);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
//     __type(key, int);
//     __uint(pinning, 1);
//     __type(value, struct something);
// } sock_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
//     __type(key, struct sock *);
//     __uint(pinning, 1);
//     __type(value, struct something);
//     __uint(max_entries, 65536);
// } sock_map SEC(".maps");

// Copy from kernel/include/trace/events/sock.h
struct bpf_sock_state_ctx {
    __u64 unused;
    void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    // for linux-4.18, 需要禁用的 GetPeerName
#ifndef DISABLE_GETPEERNAME
    __u16 protocol; // 自kernel 5.6.0 以上，protocol升级为2字节
#else
    __u8 protocol;
#endif
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
    struct something smt = {
        .a = 0x000a,
        .b = 0x000b,
        .c = 0x000c,
        .d = 0x000d,
    };
    // bpf_sk_storage_get(&sock_map, ctx->sk, &smt, BPF_SK_STORAGE_GET_F_CREATE);

    // bpf_map_update_elem(&sock_map, &ctx->sk, &smt, BPF_ANY);

    bpf_printk("in connect4, sockaddr: %p", ctx->sk);
    return SK_PASS;
}

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct bpf_sock_state_ctx *ctx)
{
    if (ctx->skaddr == NULL) {
        return BPF_OK;
    }
    struct sock *sk2 = ctx->skaddr;

#define AF_INET 2
#define AF_INET6 10

    __u16 family = BPF_CORE_READ(sk2, __sk_common.skc_family);

    if (family == AF_INET) {
        __u32 addr = BPF_CORE_READ(sk2, __sk_common.skc_daddr);
        bpf_printk("%d %pI4", family, &addr);
    } else if (family == AF_INET6) {
        struct in6_addr addr;
        BPF_CORE_READ_INTO(&addr, sk2, __sk_common.skc_v6_daddr);
        bpf_printk("%d %pI6", family, &addr);
    }
    // struct something *sm = bpf_sk_storage_get(&sock_map, ctx->skaddr, 0, 0);
    // if (sm == NULL) {
    //     bpf_printk("sock_map get return NULL");
    // }

    if (ctx->newstate == BPF_TCP_CLOSE) {}
    return BPF_OK;
}
