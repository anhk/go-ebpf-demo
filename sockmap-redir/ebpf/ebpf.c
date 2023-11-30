#include <linux/bpf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct value {
    int value;
    int value2;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, __u32);
    __uint(pinning, 1);
    __type(value, struct value);
    __uint(max_entries, 65536);
} sock_map SEC(".maps");

SEC("sockops")
int sock_setops(struct bpf_sock_ops *skops)
{
    if (skops->remote_ip4 != 0x3540a8c0) { // 192.168.64.53
        return SK_PASS;
    }
    if (skops->remote_port != bpf_ntohl(80)) { // 4字节
        return SK_PASS;
    }

    // 设置后，会有BPF_SOCK_OPS_STATE_CB消息
    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

    switch (skops->op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: { // 被动建立连接
        bpf_printk("[1] sockops, state: %d", skops->state);
        int key = bpf_get_prandom_u32();
        bpf_sock_hash_update(skops, &sock_map, &key, BPF_ANY); // 加到map中，就能收到sk_msg消息
        break;
    }
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: { // 主动建立连接
        bpf_printk("[2] sockops, state: %d", skops->state);
        int key = bpf_get_prandom_u32();
        bpf_sock_hash_update(skops, &sock_map, &key, BPF_ANY); // 加到map中，就能收到sk_msg消息
        break;
    }
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE) { // 关闭连接?
            bpf_printk("close tcp socket");
        }
    default:
        break;
    }
    return 0;
}

SEC("sk_msg")
int sock_message(struct sk_msg_md *msg)
{
    __u8 proxy[] = "PROXY TCP4 192.168.64.1 192.168.64.53 33333 80\r\n";
    int len = sizeof(proxy)-1;

    int ret = bpf_msg_push_data(msg, 0, len, 0);
    if (ret != 0) {
        bpf_printk("bpf_msg_push_data return: %d", ret);
        return SK_PASS;
    }

    void *data_end = (void *)(long)msg->data_end;
    void *data = (void *)(long)msg->data;
    
    // char *d;
    if (data + len > data_end)
        return SK_DROP;
    bpf_printk("data length %i", (__u64)msg->data_end - (__u64)msg->data);
    // d = (char *)data;
    // bpf_printk("hello sendmsg hook %i %i\n", d[0], d[1]);
    // d[0 ] = 3;
    // *dst = 5;
    __builtin_memcpy(data, proxy, len);

    // memcpy(msg->data, data, len);

    bpf_printk("--- message size: %d, diff: %d ", msg->size, msg->data_end - msg->data);
    return SK_PASS;
}
