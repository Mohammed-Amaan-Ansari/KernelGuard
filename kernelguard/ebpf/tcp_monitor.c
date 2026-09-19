#include <uapi/linux/ptrace.h>

struct sockaddr_in_t {
    u16 sin_family;
    u16 sin_port;
    u32 sin_addr;
};

struct tcp_event_t {
    u32 pid;
    u32 uid;
    u32 daddr;
    u16 dport;
    char comm[16];
};

BPF_PERF_OUTPUT(tcp_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    struct tcp_event_t event = {};
    struct sockaddr_in_t addr = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    if (args->addrlen < sizeof(addr)) {
        return 0;
    }

    if (args->uservaddr == NULL) {
        return 0;
    }

    bpf_probe_read_user(
        &addr,
        sizeof(addr),
        args->uservaddr
    );

    if (addr.sin_family != 2) {
        return 0;
    }

    event.daddr = addr.sin_addr;
    event.dport = addr.sin_port;

    tcp_events.perf_submit(
        args,
        &event,
        sizeof(event)
    );

    return 0;
}
