from pathlib import Path
from ctypes import c_uint

from bcc import BPF


def main():
    project_root = Path(__file__).resolve().parents[2]

    ebpf_file = (
        project_root
        / "kernelguard"
        / "ebpf"
        / "exec_monitor.c"
    )

    with open(ebpf_file, "r", encoding="utf-8") as file:
        bpf_program = file.read()

    bpf = BPF(text=bpf_program)

    # --------------------------------------------------
    # PID FILTER
    # --------------------------------------------------

    # 0 = monitor all processes
    target_pid_value = 0

    target_pid = bpf["target_pid"]

    key = c_uint(0)
    value = c_uint(target_pid_value)

    target_pid[key] = value

    # --------------------------------------------------
    # EVENT HANDLER
    # --------------------------------------------------

    def handle_event(cpu, data, size):
        event = bpf["exec_events"].event(data)

        comm = event.comm.decode(
            "utf-8",
            "replace"
        ).rstrip("\x00")

        filename = event.filename.decode(
            "utf-8",
            "replace"
        ).rstrip("\x00")

        print(
            f"[EXEC] "
            f"PID={event.pid} "
            f"PPID={event.ppid} "
            f"COMM={comm} "
            f"FILE={filename}"
        )

    bpf["exec_events"].open_perf_buffer(
        handle_event
    )

    # --------------------------------------------------
    # START MONITOR
    # --------------------------------------------------

    print("=" * 70)
    print("KernelGuard - eBPF Exec Monitor")
    print("=" * 70)

    if target_pid_value == 0:
        print("PID Filter : DISABLED")
        print("Monitoring all process executions.")
    else:
        print(f"PID Filter : {target_pid_value}")
        print(f"Monitoring PID {target_pid_value} only.")

    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            bpf.perf_buffer_poll()

    except KeyboardInterrupt:
        print("\nKernelGuard monitor stopped.")


if __name__ == "__main__":
    main()
