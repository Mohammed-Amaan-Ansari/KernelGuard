import os
import time

path = "/tmp/kernelguard_test.txt"

print(f"Test process PID: {os.getpid()}", flush=True)

while True:
    with open(path, "a", encoding="utf-8") as file:
        file.write("KernelGuard write test\n")

    time.sleep(2)
