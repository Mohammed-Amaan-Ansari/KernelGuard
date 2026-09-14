#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct tcp_event_t {
    u32 pid;
    u32 uid;
    u32 daddr;
    u16 dport;
    char comm[16];
};

BPF_PERF_OUTPUT(tcp_events);

TRACEPOINT_PROBE(tcp, tcp_connect)
{
    struct tcp_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    event.daddr = args->daddr;
    event.dport = args->dport;

    tcp_events.perf_submit(
        args,
        &event,
        sizeof(event)
    );

    return 0;
}
