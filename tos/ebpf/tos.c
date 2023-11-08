

#include <linux/bpf.h>
#include <linux/in.h>
// #include "vmlinux.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define IP_TOS 1

char __license[] SEC("license") = "GPL";

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->user_port == bpf_htons(80)) {
        __u32 value = 0xFC;
        int ret = bpf_setsockopt(ctx, IPPROTO_IP, IP_TOS, &value, sizeof(value));
        bpf_printk("ret: %d", ret);
    }
    return 1;
}

// -- 不支持bpf_setsockopt
// SEC("cgroup/post_bind4")
// int sock_post_bind4(struct bpf_sock *ctx)
// {
//     __u32 value = 0xEC;
//     int ret = bpf_setsockopt(ctx, IPPROTO_IP, IP_TOS, &value, sizeof(value));
//     bpf_printk("ret: %d", ret);
//     return 1;
// }

// -- bpf_setsockopt 返回 Invalid argument
// SEC("cgroup/bind6")
// int sock_bind6( struct bpf_sock_addr *ctx)
// {
//     __u32 value = 0xEC;
//     int ret = bpf_setsockopt(ctx, IPPROTO_IP, IP_TOS, &value, sizeof(value));
//     bpf_printk("ret: %d", ret);
//     return 1;
// }

// SEC("kretprobe/inet_csk_accept")
// int kretprobe__inet_csk_accept(struct pt_regs *ctx)
// {
//     struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
//     if (newsk == NULL) {
//         return 0;
//     }

//     return 0;
// }