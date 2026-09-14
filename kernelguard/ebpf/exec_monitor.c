#include <uapi/linux/ptrace.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(exec_events);

BPF_ARRAY(target_pid, u32, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct exec_event_t event = {};

    u32 key = 0;
    u32 *pid_filter;

    event.pid = bpf_get_current_pid_tgid() >> 32;

    pid_filter = target_pid.lookup(&key);

    if (pid_filter != NULL && *pid_filter != 0) {
        if (event.pid != *pid_filter) {
            return 0;
        }
    }

    event.ppid = 0;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    bpf_probe_read_user_str(
        &event.filename,
        sizeof(event.filename),
        args->filename
    );

    exec_events.perf_submit(
        args,
        &event,
        sizeof(event)
    );

    return 0;
}
