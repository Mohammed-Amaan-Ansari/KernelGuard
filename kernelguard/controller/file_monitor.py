import argparse
from ctypes import c_uint
from pathlib import Path

from bcc import BPF

from kernelguard.events.logger import EventLogger
from kernelguard.events.model import SecurityEvent


def main():
    parser = argparse.ArgumentParser(
        description="KernelGuard eBPF write syscall monitor"
    )

    parser.add_argument(
        "pid",
        type=int,
        help="PID of the process to monitor"
    )

    args = parser.parse_args()

    if args.pid <= 0:
        raise ValueError("PID must be greater than 0")

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

    # Configure target PID
    target_pid = bpf["target_pid"]

    key = c_uint(0)
    value = c_uint(args.pid)

    target_pid[key] = value

    # Central event logger
    logger = EventLogger(
        project_root / "logs" / "kernelguard.jsonl"
    )

    def handle_event(cpu, data, size):
        event = bpf["file_events"].event(data)

        comm = event.comm.decode(
            "utf-8",
            "replace"
        ).rstrip("\x00")

        security_event = SecurityEvent(
            event_type="FILE_WRITE",
            pid=event.pid,
            uid=event.uid,
            comm=comm,
            data={
                "syscall": "write"
            }
        )

        logger.log(security_event)
        logger.print_event(security_event)

    bpf["file_events"].open_perf_buffer(
        handle_event
    )

    print("=" * 70)
    print("KernelGuard - eBPF File Write Monitor")
    print("=" * 70)
    print(f"Target PID     : {args.pid}")
    print("Hook           : __x64_sys_write")
    print("Monitoring     : Write syscalls from target PID only")
    print("Event Pipeline : ENABLED")
    print("Log File       : logs/kernelguard.jsonl")
    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            bpf.perf_buffer_poll(timeout=100)

    except KeyboardInterrupt:
        print("\nKernelGuard file monitor stopped.")

    finally:
        try:
            bpf.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    main()
