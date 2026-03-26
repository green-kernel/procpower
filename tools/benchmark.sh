#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./benchmark.sh [options]

Runs a mixed workload to exercise CPU, memory, disk, network, and wakeups
while you collect energy logs. Run energy-logger.sh in another terminal.

Options:
  --duration SEC        seconds per phase / sub-phase (default: 20)
  --rounds N            repeat all phases N times (default: 1)
  --tmpdir DIR          directory for disk payloads (default: /tmp/procpower-bench)
  --file-mb MB          size of disk IO file in MB (default: 512)
  --mem-mb MB           memory stress size in MB (default: 512)
  --cpu-workers N       CPU worker processes (default: nproc)
  --wakeup-threads N    wakeup threads (default: nproc)
  --net-url URL         download URL for network phase
  -h, --help            show this help

Notes:
  - For real disk IO, set --tmpdir to a disk-backed path (not tmpfs).
  - Network phase downloads from the internet; ensure you have connectivity.
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }

DURATION=20
ROUNDS=1
TMPDIR="/tmp/procpower-bench"
FILE_MB=512
MEM_MB=512
CPU_WORKERS="$(nproc)"
WAKEUP_THREADS="$(nproc)"
NET_URL="https://nbg1-speed.hetzner.com/100MB.bin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --rounds) ROUNDS="$2"; shift 2 ;;
        --tmpdir) TMPDIR="$2"; shift 2 ;;
        --file-mb) FILE_MB="$2"; shift 2 ;;
        --mem-mb) MEM_MB="$2"; shift 2 ;;
        --cpu-workers) CPU_WORKERS="$2"; shift 2 ;;
        --wakeup-threads) WAKEUP_THREADS="$2"; shift 2 ;;
        --net-url) NET_URL="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

if ! have timeout; then
    echo "timeout not found; install coreutils." >&2
    exit 1
fi

mkdir -p "$TMPDIR"
IO_FILE="$TMPDIR/bench-io.bin"

cleanup() {
    rm -f "$IO_FILE"
}
trap cleanup EXIT

trap 'echo "Aborted."; pkill -P $$; exit 1' INT


phase() {
    echo
    echo "== $1 =="
}

run_timeout() {
    # timeout exits 124 on expected time limit; don't treat as failure
    timeout "$@" || {
        status=$?
        if [[ $status -ne 124 ]]; then
            return $status
        fi
    }
}

cpu_phase() {
    phase "cpu (ramping)"

    local max_workers="$CPU_WORKERS"
    local workers=1

    while (( workers <= max_workers )); do
        echo "Running with $workers CPU workers for ${DURATION}s"

        stress-ng --cpu "$workers" --cpu-method matrixprod --timeout "${DURATION}s" --metrics-brief

        ((workers++))
    done
}

mem_phase() {
    phase "memory"
    stress-ng --vm 1 --vm-bytes "${MEM_MB}M" --timeout "${DURATION}s" --metrics-brief
}

disk_write_phase() {
    phase "disk write"
    local count=$((FILE_MB / 4))
    if (( count < 1 )); then count=1; fi
    run_timeout "${DURATION}s" bash -c "while :; do dd if=/dev/zero of='$IO_FILE' bs=4M count=$count conv=fdatasync status=none; done"
}

disk_read_phase() {
    phase "disk read"
    if [[ ! -f "$IO_FILE" ]]; then
        echo "disk file missing; skipping read phase"
        return
    fi
    local count=$((FILE_MB / 4))
    if (( count < 1 )); then count=1; fi
    run_timeout "${DURATION}s" bash -c "while :; do dd if='$IO_FILE' of=/dev/null bs=4M count=$count status=none; done"
}

net_phase() {
    phase "network (remote download)"
    if have curl; then
        run_timeout "${DURATION}s" bash -c "while :; do curl -sSfL --output /dev/null '${NET_URL}'; done"
        return
    fi
    if have wget; then
        run_timeout "${DURATION}s" bash -c "while :; do wget -q -O /dev/null '${NET_URL}'; done"
        return
    fi
    echo "curl/wget not found; Please install to run net phase of benchmark ..." >&2
    exit 1

}

idle_phase() {
    phase "idle (sleeping)"
    sleep "${DURATION}"
}


wakeups_phase() {
    phase "wakeups"
    stress-ng --switch "$WAKEUP_THREADS" --timeout "${DURATION}s" --metrics-brief
}

syscall_phase() {
    phase "syscall"
    stress-ng --syscall "$CPU_WORKERS" --timeout "${DURATION}s" --metrics-brief
}

for ((i=1; i<=ROUNDS; i++)); do
    echo "Round $i/$ROUNDS"
    cpu_phase
    mem_phase
    disk_write_phase
    disk_read_phase
    net_phase
    idle_phase
    wakeups_phase
    syscall_phase
done

echo
echo "Benchmark complete."
