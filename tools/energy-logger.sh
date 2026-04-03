#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
    echo "❌  This script must be run as root (use sudo?)." >&2
    exit 1
fi

# 1) Create a unique log file in /tmp (e.g. /tmp/energy‑abcd1234.log) if nothing supplied. Otherwise take user supplied dir which must also be writeable
LOGFILE=$(mktemp /tmp/energy-XXXXXXXX.log)
MCP_BIN=/home/gc/green-metrics-tool/metric_providers/psu/energy/ac/mcp/machine/metric-provider-binary

# Function to safely call MCP if binary exists
call_mcp() {
    if [[ -x "$MCP_BIN" ]]; then
        "$MCP_BIN" "$@"
    else
        echo "⚠️  MCP binary not found at $MCP_BIN" >&2
    fi
}

chmod 777 $LOGFILE

echo "Logging to $LOGFILE"

# 2) Counters and timers
iterations=0
last_report=$(date +%s)

# Start MCP safely
call_mcp -o              # reset
call_mcp -e -o           # start energy accumulator

# 3) Infinite sampling loop
while : ; do
    # append reading
    # sudo cat /sys/kernel/debug/energy/all >> "$LOGFILE"
    sudo cat /sys/kernel/debug/energy/sys >> "$LOGFILE"
    echo -n "psu_energy_ac_mcp_machine=" >> "$LOGFILE"
    call_mcp -e -o >> "$LOGFILE"
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
