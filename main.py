import os
from bcc import BPF


PMS_LIST = ("apt",)


def handle_pms(filename):
    """Package manager system"""

    app_name = os.path.basename(filename)
    if app_name in PMS_LIST:
        print("<<", app_name)


# Define eBPF program
program = """
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    bpf_trace_printk("%s\\n", args->filename);
    return 0;
}
"""


# Load and attach
bpf = BPF(text=program)


def main():
    while True:
        (_, _, _, _, _, msg) = bpf.trace_fields()
        handle_pms(msg.decode())


if __name__ == "__main__":
    print("Tracing exec syscalls... Ctrl+C to exit")

    try:
        main()
    except KeyboardInterrupt:
        exit()
