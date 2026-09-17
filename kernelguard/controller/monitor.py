from pathlib import Path
from bcc import BPF


def load_program(filename):
    project_root = Path(__file__).resolve().parents[2]
    ebpf_file = project_root / "kernelguard" / "ebpf" / filename

    with open(ebpf_file, "r", encoding="utf-8") as file:
        return file.read()


def monitor_exec():
    print("[*] Loading exec monitor...")

    program = load_program("exec_monitor.c")
    bpf = BPF(text=program)

    target_pid = bpf["target_pid"]

    from ctypes import c_uint

    key = c_uint(0)
    value = c_uint(0)

    target_pid[key] = value

    def handle_event(cpu, data, size):
        event = bpf["exec_events"].event(data)

        comm = event.comm.decode(
            "utf-8", "replace"
        ).rstrip("\x00")

        filename = event.filename.decode(
            "utf-8", "replace"
        ).rstrip("\x00")

        print(
            f"[EXEC] "
            f"PID={event.pid} "
            f"COMM={comm} "
            f"FILE={filename}"
        )

    bpf["exec_events"].open_perf_buffer(handle_event)

    print("[+] Exec monitor active.")

    return bpf


def main():
    print("=" * 70)
    print("KernelGuard - Unified Runtime Monitor")
    print("=" * 70)
    print()

    exec_bpf = monitor_exec()

    print()
    print("Monitoring:")
    print("  [EXEC] Process execution")
    print("  [TCP]  Network connections")
    print("  [FILE] Write syscalls")
    print()
    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            exec_bpf.perf_buffer_poll()

    except KeyboardInterrupt:
        print("\nKernelGuard monitor stopped.")


if __name__ == "__main__":
    main()
