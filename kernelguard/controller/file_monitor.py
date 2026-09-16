from pathlib import Path

from bcc import BPF


def main():
    project_root = Path(__file__).resolve().parents[2]

    ebpf_file = (
        project_root
        / "kernelguard"
        / "ebpf"
        / "file_monitor.c"
    )

    with open(ebpf_file, "r", encoding="utf-8") as file:
        bpf_program = file.read()

    bpf = BPF(text=bpf_program)

    bpf.attach_kprobe(
        event="__x64_sys_write",
        fn_name="trace_sys_write"
    )

    def handle_event(cpu, data, size):
        event = bpf["file_events"].event(data)

        comm = event.comm.decode(
            "utf-8",
            "replace"
        ).rstrip("\x00")

        print(
            f"[FILE_WRITE] "
            f"PID={event.pid} "
            f"UID={event.uid} "
            f"COMM={comm}"
        )

    bpf["file_events"].open_perf_buffer(
        handle_event
    )

    print("=" * 70)
    print("KernelGuard - eBPF File Write Monitor")
    print("=" * 70)
    print("Hook       : __x64_sys_write")
    print("Monitoring : File write syscall events")
    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            bpf.perf_buffer_poll()

    except KeyboardInterrupt:
        print("\nKernelGuard file monitor stopped.")


if __name__ == "__main__":
    main()
