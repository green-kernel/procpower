#!/usr/bin/env bash
#
set -euo pipefail
IFS=$'\n\t'

#######################################
# utilities
#######################################
die()  { echo "❌  $*" >&2; exit 1; }
pass() { echo "✅  $*"; }

need() { command -v "$1" &>/dev/null || die "missing tool: $1"; }
need make; need modprobe; need dmesg; need docker

MOD_NAME=energy_proc

#######################################
# cleanup helper (runs on EXIT)
#######################################
mounted_debugfs=0
cleanup() {
    modprobe -r "$MOD_NAME" 2>/dev/null || true
    (( mounted_debugfs )) && umount /sys/kernel/debug
}
trap cleanup EXIT

#######################################
# ensure module is NOT loaded
#######################################
modprobe -r "$MOD_NAME" 2>/dev/null || true

#######################################
# 0. build the module
#######################################
SRC_DIR=${1:-src}
[[ -d "$SRC_DIR" ]] || die "source directory “$SRC_DIR” not found"

echo "• Building module in $SRC_DIR …"
cd "$SRC_DIR" || die "failed to change to source directory $SRC_DIR"
make clean >/dev/null 2>&1 || true
make  >/dev/null
cd ..

MODULE=$(find "$SRC_DIR" -maxdepth 1 -name 'energy_proc*.ko' -print -quit)
[[ -f "$MODULE" ]] || die "build failed - .ko not found in $SRC_DIR"
pass "module built → $(basename "$MODULE")"

#######################################
# 1. make sure debugfs is mounted
#######################################
if ! mountpoint -q /sys/kernel/debug; then
    mount -t debugfs none /sys/kernel/debug
    mounted_debugfs=1
fi

#######################################
# 2. load the module
#######################################
echo "• Loading $MODULE …"
dmesg -C
cd "$SRC_DIR" || die "failed to change to source directory $SRC_DIR"
make install >/dev/null || die "module install failed"
cd ..

sleep 1                     # allow first sampling tick

dmesg | grep -q "$MOD_NAME" \
  && pass "module inserted and logged to dmesg" \
  || die "module did not announce itself in dmesg"

#######################################
# 3. debugfs sanity
#######################################
DBG=/sys/kernel/debug/energy/all
[[ -r $DBG ]] || die "$DBG missing or unreadable"

dbg_out=$(head -n 5 "$DBG") || die "reading $DBG failed"
grep -q '^timestamp=' <<<"$dbg_out" \
  && pass "$DBG returns metrics" \
  || die "$DBG lacks expected keys"

#######################################
# 4. proc files on the host
#######################################
for f in /proc/energy/all /proc/energy/cgroup; do
    [[ -r $f ]] || die "$f is missing"
done
pass "/proc/energy/{all,cgroup} present on host"

#######################################
# 5. container checks
#######################################
img=ubuntu:24.04
docker pull -q "$img" >/dev/null

# (a) /proc/energy/all must fail
set +e
docker run --rm --security-opt=no-new-privileges --pull=never "$img" \
       bash -c 'cat /proc/energy/all 2>/dev/null'
all_rc=$?
set -e
[[ $all_rc -ne 0 ]] \
    && pass "cat /proc/energy/all fails inside container (expected)" \
    || die "/proc/energy/all readable inside container – should be blocked"

# (b) /proc/energy/cgroup must succeed
cg_out=$(docker run --rm --security-opt=no-new-privileges --pull=never "$img" \
           bash -c 'cat /proc/energy/cgroup | head -n 20')
grep -q '^pid=' <<<"$cg_out" \
    && pass "/proc/energy/cgroup works inside container" \
    || die "/proc/energy/cgroup did not return expected data"

#######################################
# all good!
#######################################
pass "all checks passed - module looks good 🎉"
