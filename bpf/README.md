# BPF process event monitor

Monitors process exec/fork/exit events via eBPF tracepoints and streams them to stdout for `process_metrics.sh`.

## Build (offline, no internet required)

```bash
# 1. Install build dependencies
make deps-apt          # Astra Linux / Debian / Ubuntu
make deps-yum          # RHEL / CentOS / Rocky

# 2. Build
make all               # builds bpftool from source + process_monitor_bpf
make all CLANG=clang-10  # if clang is versioned (e.g. Astra Linux)
```

## Runtime capabilities

`process_metrics.sh` can run **without root**. Minimum required Linux capabilities:

| Capability | Purpose | Required for |
|---|---|---|
| `CAP_BPF` | Load BPF programs (kernel 5.8+) | event mode (optional) |
| `CAP_PERFMON` | Attach to tracepoints (`sched_process_exec/fork/exit`) | event mode (optional) |

Without `CAP_BPF`/`CAP_PERFMON`, the script automatically falls back to poll-only mode.

### Setup options

**Option 1: systemd unit (recommended)**
```ini
[Service]
User=process_metrics
AmbientCapabilities=CAP_BPF CAP_PERFMON
```

**Option 2: Run as root** (simplest but least secure)
```bash
sudo ./process_metrics.sh
```

**Option 3: Poll-only without BPF caps**
```bash
bash process_metrics.sh --poll-only
```

### Kernel requirements

- `CONFIG_BPF_SYSCALL=y` (for event mode)
- `CONFIG_BPF_EVENTS=y` (tracepoint support)
- BTF enabled (`/sys/kernel/btf/vmlinux` must exist for CO-RE)

### Regenerating vmlinux.h

If the target kernel differs from the build host:
```bash
make vmlinux    # uses bpftool btf dump from running kernel
```

## Directory structure

```
src/                            — source code
  process_monitor_bpf.bpf.c    — BPF kernel program (tracepoints)
  process_monitor_bpf.c         — userspace loader
  vmlinux.h                     — kernel type definitions (CO-RE)
  bpftool/                      — vendored bpftool sources
build/                          — generated artifacts (gitignored)
  bpftool                       — locally built bpftool
  process_monitor_bpf           — final binary
  process_monitor_bpf.bpf.o    — compiled BPF ELF
  process_monitor_bpf.skel.h   — auto-generated skeleton
```
