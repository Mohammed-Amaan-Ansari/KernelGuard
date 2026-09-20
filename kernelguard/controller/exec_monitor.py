from ctypes import c_uint
from pathlib import Path

from bcc import BPF

from kernelguard.events.logger import EventLogger
from kernelguard.events.model import SecurityEvent


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

    # PID filtering
    target_pid_value = 0

    target_pid = bpf["target_pid"]

    key = c_uint(0)
    value = c_uint(target_pid_value)

    target_pid[key] = value

    # Central event logger
    logger = EventLogger(
        project_root / "logs" / "kernelguard.jsonl"
    )

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

        security_event = SecurityEvent(
            event_type="EXEC",
            pid=event.pid,
            uid=0,
            comm=comm,
            data={
                "filename": filename
            }
        )

        logger.log(security_event)
        logger.print_event(security_event)

    bpf["exec_events"].open_perf_buffer(
        handle_event
    )

    print("=" * 70)
    print("KernelGuard - eBPF Exec Monitor")
    print("=" * 70)

    if target_pid_value == 0:
        print("PID Filter : DISABLED")
        print("Monitoring all process executions.")
    else:
        print(f"PID Filter : {target_pid_value}")
        print(f"Monitoring PID {target_pid_value} only.")

    print("Event Pipeline : ENABLED")
    print("Log File       : logs/kernelguard.jsonl")
    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            bpf.perf_buffer_poll(timeout=100)

    except KeyboardInterrupt:
        print("\nKernelGuard exec monitor stopped.")

    finally:
        try:
            bpf.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    main()
