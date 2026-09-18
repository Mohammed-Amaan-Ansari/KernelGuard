#include <uapi/linux/ptrace.h>

struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[16];
};

BPF_PERF_OUTPUT(file_events);

/*
 * target_pid[0] = PID to monitor.
 * 0 means monitoring is disabled until a PID is provided.
 */
BPF_ARRAY(target_pid, u32, 1);

int trace_sys_write(struct pt_regs *ctx)
{
    struct file_event_t event = {};

    u32 key = 0;
    u32 *pid_filter;

    event.pid = bpf_get_current_pid_tgid() >> 32;

    pid_filter = target_pid.lookup(&key);

    /*
     * Only monitor the selected PID.
     */
    if (pid_filter == NULL || *pid_filter == 0) {
        return 0;
    }

    if (event.pid != *pid_filter) {
        return 0;
    }

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
