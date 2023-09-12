#include <linux/bpf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} events SEC(".maps");


struct event {
    int pid;
    int uid;
    int foo;
    int bar;
};

SEC("kprobe/sys_execve")
int bpf_prog(void* ctx)
{
    struct event event;
//    u32 uid = (u32)bpf_get_current_uid_gid();
//    u32 pid = (u32)bpf_get_current_pid_tgid();

    __u32 pid = 0x01020304;
    __u32 uid = 0x05060708;

    event.pid = (int)pid;
    event.uid = (int)uid;
    event.foo = 0x0a0b0c0d;
    event.bar = 0x09090909;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    bpf_printk("hello world: %d %d", pid, uid);
    return 0;
}
