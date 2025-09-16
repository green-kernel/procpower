#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
    echo "❌  This script must be run as root (use sudo?)." >&2
    exit 1
fi

# 1) Create a unique log file in /tmp (e.g. /tmp/energy‑abcd1234.log)
LOGFILE=$(mktemp /tmp/energy-XXXXXXXX.log)
echo "Logging to $LOGFILE"

# 2) Counters and timers
iterations=0
last_report=$(date +%s)

# 3) Infinite sampling loop
while : ; do
    # append reading
    # sudo cat /sys/kernel/debug/energy/all >> "$LOGFILE"
    sudo cat /sys/kernel/debug/energy/sys >> "$LOGFILE"

    echo '-------'                    >> "$LOGFILE"

    sleep 0.1                         # ≈100 Hz sample rate
    ((iterations++))

    # every 10 s print how many iterations have run so far
    now=$(date +%s)
    if (( now - last_report >= 10 )); then
        printf 'Iterations so far: %d\n' "$iterations"
        last_report=$now
    fi
done
