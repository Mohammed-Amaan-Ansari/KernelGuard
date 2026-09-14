#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct tcp_event_t {
    u32 pid;
    u32 uid;
    u32 daddr;
    u16 dport;
    char comm[16];
};

BPF_PERF_OUTPUT(tcp_events);

int trace_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    struct tcp_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    if (sk == NULL) {
        return 0;
    }

    event.daddr = sk->__sk_common.skc_daddr;
    event.dport = sk->__sk_common.skc_dport;

    event.dport = event.dport >> 8 |
                  event.dport << 8;

    tcp_events.perf_submit(
        ctx,
        &event,
        sizeof(event)
    );

    return 0;
}
