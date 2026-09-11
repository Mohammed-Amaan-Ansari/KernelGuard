#include <uapi/linux/ptrace.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    char comm[16];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct exec_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;

    event.ppid = 0;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    exec_events.perf_submit(args, &event, sizeof(event));

    return 0;
}
