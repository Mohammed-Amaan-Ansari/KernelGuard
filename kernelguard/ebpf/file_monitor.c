#include <uapi/linux/ptrace.h>

struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[16];
};

BPF_PERF_OUTPUT(file_events);

int trace_sys_write(struct pt_regs *ctx)
{
    struct file_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    file_events.perf_submit(
        ctx,
        &event,
        sizeof(event)
    );

    return 0;
}
