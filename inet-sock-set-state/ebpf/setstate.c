#include <linux/bpf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

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
    return SK_PASS;
}

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct bpf_sock_state_ctx *ctx)
{
    return BPF_OK;
}
