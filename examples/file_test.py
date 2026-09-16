from pathlib import Path

path = Path("/tmp/kernelguard_test.txt")

path.write_text(
    "KernelGuard file monitoring test\n",
    encoding="utf-8"
)

print("File written successfully")
