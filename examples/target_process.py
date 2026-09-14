import os
import time


print("Target process started")
print(f"PID: {os.getpid()}")

while True:
    time.sleep(1)
