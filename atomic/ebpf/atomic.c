#include <linux/bpf.h>
#include <linux/string.h> // for memset

#include "bpf_endian.h"
#include "bpf_helpers.h"

static __u64 data = 10086;
struct bpf_spin_lock lock;

void a()
{
    // 4.18 不支持：
    // * 编译错误：Cannot select: 0x55c89940f1e8: i64,ch = AtomicCmpSwap<(load store seq_cst seq_cst 8 on @data)>
    // __u64 old = __sync_val_compare_and_swap(&data, 10086, 10010);
    // bpf_printk("old: %d",old);
}

void b()
{
    // 4.18: 加载错误：invalid argument: BPF_STX uses reserved fields
    // __u64 old = __sync_fetch_and_add(&data, 1);
    // bpf_printk("old: %d", old);
    // __sync_fetch_and_sub(&data, 1);
}

void c()
{
    // 4.18: reference to "lock" in section SHN_COMMON: not supported
    // bpf_spin_lock(&lock); // function calls are not allowed while holding a lock
    // data++;
    // bpf_spin_unlock(&lock);
    // bpf_printk("after unlock: %d", data);
}

struct entry {
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 16);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map001 SEC(".maps");

void d()
{
    // 4.18: OK
    int k = 1;
    struct entry *e = bpf_map_lookup_elem(&map001, &k);
    if (e == NULL) {
        struct entry ee;
        memset(&ee, 0, sizeof(struct entry));
        bpf_map_update_elem(&map001, &k, &ee, BPF_ANY);

        e = bpf_map_lookup_elem(&map001, &k);
    }

    if (e != NULL) {
        bpf_spin_lock(&e->lock);
        data++;
        bpf_spin_unlock(&e->lock);
        bpf_printk("after unlock: %d", data);
    }
}

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
    a();
    b();
    c();
    d();

    return 1;
}

char __license[] SEC("license") = "GPL";
