#include <uapi/linux/ptrace.h>

struct tcp_event_t {
    u32 pid;
    u32 uid;
    u32 daddr;
    u16 dport;
    char comm[16];
};

BPF_PERF_OUTPUT(tcp_events);

/*
 * tcp_v4_connect(struct sock *sk, ...)
 *
 * We intentionally do not include <net/sock.h>.
 * The WSL kernel headers used by BCC have an
 * incomplete struct bpf_task_work definition.
 *
 * BCC's bpf_probe_read_kernel() is used to safely
 * read the required fields from the socket structure.
 */

int trace_tcp_v4_connect(struct pt_regs *ctx)
{
    struct tcp_event_t event = {};

    void *sk;
    u32 daddr;
    u16 dport;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    sk = (void *)PT_REGS_PARM1(ctx);

    if (sk == NULL) {
        return 0;
    }

    /*
     * On Linux, skc_daddr and skc_dport are located
     * inside struct sock_common.
     *
     * These offsets are kernel-version dependent.
     *
     * We will validate the result against the WSL
     * kernel before relying on it.
     */

    bpf_probe_read_kernel(
        &daddr,
        sizeof(daddr),
        sk + 24
    );

    bpf_probe_read_kernel(
        &dport,
        sizeof(dport),
        sk + 28
    );

    event.daddr = daddr;

    /*
     * Network ports are stored in network byte order.
     */
    event.dport = (dport >> 8) | (dport << 8);

    tcp_events.perf_submit(
        ctx,
        &event,
        sizeof(event)
    );

    return 0;
}
