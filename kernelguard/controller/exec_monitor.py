from pathlib import Path

from bcc import BPF


def main():
    project_root = Path(__file__).resolve().parents[2]

    ebpf_file = project_root / "kernelguard" / "ebpf" / "exec_monitor.c"

    with open(ebpf_file, "r", encoding="utf-8") as file:
        bpf_program = file.read()

    bpf = BPF(text=bpf_program)

    class ExecEvent:
        def __init__(self, event):
            self.pid = event.pid
            self.ppid = event.ppid
            self.comm = event.comm.decode("utf-8", "replace")

    def handle_event(cpu, data, size):
        raw_event = bpf["exec_events"].event(data)
        event = ExecEvent(raw_event)

        print(
            f"[EXEC] "
            f"PID={event.pid} "
            f"PPID={event.ppid} "
            f"COMM={event.comm}"
        )

    bpf["exec_events"].open_perf_buffer(handle_event)

    print("=" * 60)
    print("KernelGuard - eBPF Exec Monitor")
    print("=" * 60)
    print("Monitoring process execution...")
    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nKernelGuard monitor stopped.")


if __name__ == "__main__":
    main()
