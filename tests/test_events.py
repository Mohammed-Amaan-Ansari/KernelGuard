from kernelguard.events.model import SecurityEvent
from kernelguard.events.logger import EventLogger


def main():
    event = SecurityEvent(
        event_type="EXEC",
        pid=1234,
        uid=1000,
        comm="bash",
        data={
            "filename": "/usr/bin/ls"
        }
    )

    logger = EventLogger(
        "logs/test_kernelguard.jsonl"
    )

    logger.log(event)
    logger.print_event(event)

    print("Event pipeline test passed.")


if __name__ == "__main__":
    main()
