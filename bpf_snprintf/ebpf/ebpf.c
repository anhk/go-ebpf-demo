#include <linux/bpf.h>

#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

static inline __u32 _w(int d)
{
    __u32 w = 0;
    while (w < 16 && d > 0) {
        w++;
        d = d / 10;
    }
    return w;
}

static inline __u32 _d(char *buff, __u32 size, __u32 d)
{
    __u32 w = _w(d);
    w = w > size ? size : w;
    __u32 r = w;

    if (size > 0 && d == 0) {
        buff[0] = '0';
        return 1;
    }
    while (w > 0) {
        buff[w - 1] = d % 10 + '0';
        d = d / 10;
        w--;
    }
    return r;
}

static inline __u32 _s(char *buff, __u32 size, char *str)
{
    __u32 i;
    for (i = 0; i < size && str[i] != 0; i++) {
        buff[i] = str[i];
    }
    return i;
}

static inline __u32 _ip4(char *buff, __u32 size, __u32 ip)
{
    __u32 r = 0;
    r += _d(buff + r, size - r, ((__u8 *)&ip)[0]);
    r += _s(buff + r, size - r, ".");
    r += _d(buff + r, size - r, ((__u8 *)&ip)[1]);
    r += _s(buff + r, size - r, ".");
    r += _d(buff + r, size - r, ((__u8 *)&ip)[2]);
    r += _s(buff + r, size - r, ".");
    r += _d(buff + r, size - r, ((__u8 *)&ip)[3]);
    return r;
}

int doit(__u32 ip)
{
    char buff[14] = {};

    int r = _ip4(buff, sizeof(buff), ip);
    buff[13] = 0;

    bpf_printk("r: %d, buff: %s", r, buff);
    bpf_printk("%d.%d.%d.%d", ((__u8 *)&ip)[0], ((__u8 *)&ip)[1], ((__u8 *)&ip)[2], ((__u8 *)&ip)[3]);

    return 0;
}

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
    doit(ctx->user_ip4);
    return 1;
}