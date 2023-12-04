#include <linux/bpf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

static inline int _w(__u32 d)
{
    int i;

#pragma unroll(16)
    for (i = 0; i < 16; i++) {
        if (d == 0) {
            break;
        }
        d = d / 10;
    }
    return i;
}

static inline int _d(char *buff, int size, __u32 d)
{
    int w = _w(d);

    w = w > size ? size : w;

    if (size > 0 && d == 0) {
        buff[0] = '0';
        return 1;
    }

    int i;
#pragma unroll(16)
    for (i = 0; i < w; i++) {
        buff[w - i - 1] = d % 10 + '0';
        d = d / 10;
    }

    return w;
}

static inline int _s(char *buff, int size, char *str, int slen)
{
    int i;
    if (size < slen) {
        slen = size;
    }

#pragma unroll(16)
    for (i = 0; i < slen && str[i] != 0; i++) {
        buff[i] = str[i];
    }
    return slen;
}

static inline int _ip4(char *buff, int size, __u32 ip)
{
    int r = 0;
    r += _d(buff + r, size - r, ((__u8 *)&ip)[0]);
    r += _s(buff + r, size - r, ".", 1);
    r += _d(buff + r, size - r, ((__u8 *)&ip)[1]);
    r += _s(buff + r, size - r, ".", 1);
    r += _d(buff + r, size - r, ((__u8 *)&ip)[2]);
    r += _s(buff + r, size - r, ".", 1);
    r += _d(buff + r, size - r, ((__u8 *)&ip)[3]);
    return r;
}

static inline int _proxy_tcp4(char *buff, int size, __u32 sip, __u32 dip, __u16 sport, __u16 dport)
{
    int r = 0;
    r += _s(buff + r, size - r, "PROXY TCP4 ", 11);
    r += _ip4(buff + r, size - r, sip);
    r += _s(buff + r, size - r, " ", 1);
    r += _ip4(buff + r, size - r, dip);
    r += _s(buff + r, size - r, " ", 1);
    r += _d(buff + r, size - r, bpf_ntohs(sport));
    r += _s(buff + r, size - r, " ", 1);
    r += _d(buff + r, size - r, bpf_ntohs(dport));
    r += _s(buff + r, size - r, "\r\n", 2);
    return r;
}

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != 2) {
        return 1;
    }
    bpf_printk("%d.%d.%d.%d", ((__u8 *)&ctx->user_ip4)[0], ((__u8 *)&ctx->user_ip4)[1], ((__u8 *)&ctx->user_ip4)[2],
               ((__u8 *)&ctx->user_ip4)[3]);

    char buff[64] = {};
    int r = _proxy_tcp4(buff, sizeof(buff), 0x33333333, ctx->user_ip4, 0x4344, ctx->user_port);
    buff[sizeof(buff) - 1] = 0;
    bpf_printk("[%d] == %s", r, buff);

    return 1;
}