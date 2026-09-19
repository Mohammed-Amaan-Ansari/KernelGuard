import socket
import struct
from pathlib import Path

from bcc import BPF


def ipv4_to_string(address):
    return socket.inet_ntoa(
        struct.pack("<I", address)
    )


def main():
    project_root = Path(__file__).resolve().parents[2]

    ebpf_file = (
        project_root
        / "kernelguard"
        / "ebpf"
        / "tcp_monitor.c"
    )

    with open(ebpf_file, "r", encoding="utf-8") as file:
        bpf_program = file.read()

    bpf = BPF(text=bpf_program)

    def handle_event(cpu, data, size):
        event = bpf["tcp_events"].event(data)

        comm = event.comm.decode(
            "utf-8",
            "replace"
        ).rstrip("\x00")

        destination = ipv4_to_string(event.daddr)

        port = socket.ntohs(event.dport)

        print(
            f"[TCP] "
            f"PID={event.pid} "
            f"UID={event.uid} "
            f"COMM={comm} "
            f"DST={destination} "
            f"PORT={port}",
            flush=True
        )

    bpf["tcp_events"].open_perf_buffer(
        handle_event
    )

    print("=" * 70)
    print("KernelGuard - eBPF TCP Monitor")
    print("=" * 70)
    print("Hook       : sys_enter_connect")
    print("Monitoring : IPv4 TCP connection attempts")
    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            bpf.perf_buffer_poll(timeout=100)

    except KeyboardInterrupt:
        print("\nKernelGuard TCP monitor stopped.")

    finally:
        try:
            bpf.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    main()
