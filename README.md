# procpower / energy_proc
A Linux kernel module that exposes per‑PID runtime, I/O and energy‑related statistics—including Intel RAPL readings—via /proc and debugfs. It is designed for lightweight, high‑frequency sampling so that userspace can build accurate power‑ or carbon‑aware schedulers, profilers and monitors. When you run it on the host, the same metrics are surfaced securely inside every Docker container, preserving isolation while giving full per‑cgroup visibility. An extensible energy model is built‑in—collect samples with the helper script, retrain the weights, and tailor the score to your hardware or carbon‑intensity signals. The module also runs inside virtual machines; because raw RAPL energy counters are absent, the model falls back to workload metrics and absolute energy estimates are less precise.

## Thank you

This work has been made possible by the [Prototype Fund](https://www.prototypefund.de/), [Catalyst Fund](https://greenscreen.network/en/blog/announcing-the-new-catalyst-fund-awardees/) and [Green Coding Solutions](https://www.green-coding.io/)

## Table of Contents
1. [Features](#features)
1. [Requirements](#requirements)
1. [Quick Start](#quick-start)
1. [Running Inside Virtual Machines](#running-inside-virtualmachines)
1. [Sampling Interval & Weighting](#sampling-interval--weighting)
1. [Reading the Metrics](#reading-the-metrics)
1. [Data Collection Helper](#data-collection-helper)
1. [Model](#model)
1. [Test](#test)
1. [Troubleshooting](#troubleshooting)
1. [Contributing](#contributing)

## Features
* **Per‑process metrics**: CPU time, RSS memory, disk I/O, network packets, context switch/wakeup counts and (optionally) retired instructions via PMU.
* **Energy accounting**: Integrates Intel RAPL MSRs (`PP0`/core and `PSYS`) to compute energy usage in µJ.
* **Dynamic sampling interval**: Run‑time adjustable via the `sample_ns` module parameter.
* **Weight‑based energy model**: Each metric has a tunable weight (`w_cpu_ns`, `w_mem_bytes`, …); the weighted sum is exported as `energy=<fixed‑point‑milliJ>` in each record.
* **Container aware**: `/proc/energy/cgroup` only shows processes in the caller’s default cgroup; `/proc/energy/all` and `debugfs/.../all` are root‑only.
* **Low overhead**: Uses RCU look‑ups, rhashtable and per‑CPU workqueue.  Sampling at 100 ms costs <0.3 % CPU on a 16‑core host.
* **VM**: Works in VMs but accuracy will drop. 

## Requirements
|             | Minimum | Notes |
|-------------|---------|-------|
| Linux kernel| **5.15**| Built‑in `CONFIG_PERF_EVENTS`, `CONFIG_KPROBES`, `CONFIG_TRACEPOINTS`, `CONFIG_TASK_IO_ACCOUNTING`, `CONFIG_SCHEDSTATS` (optional). |
| CPU         | Intel ≥ SandyBridge<br/>or Zen / other x86_64 | RAPL energy only on Intel; AMD Zen counts but no MSR‑based energy yet. |
| Tool‑chain   | `gcc`, `make`, `bc`, `bash` |
| Headers      | `linux-headers-$(uname -r)` |
| Debug FS     | `/sys/kernel/debug` mounted |

### Ubuntu 24.04 LTS / 25.04
```bash
sudo apt update
sudo apt install build-essential git bc libtraceevent-dev libtracefs-dev linux-headers-$(uname -r)
```

### Fedora 42
```bash
sudo dnf install @development-tools kernel-devel kernel-headers elfutils-libelf-devel git bc trace-cmd
```

Other distros: install the equivalent of *kernel‑headers* and *build‑essential*.

> 💡 **Tip**: When compiling against a custom kernel tree, export `KDIR=/path/to/linux` before running `make`.



## Quick Start
```bash
# Clone & build
$ git clone https://github.com/green-kernel/procpower.git && cd procpower/src
$ make

# Load with default 100 ms sampling
$ sudo make install

# See overall energy since boot (root‑only)
$ sudo cat /proc/energy/all

# Watch processes in your current cgroup (non‑root allowed)
$ watch -n0.5 cat /proc/energy/cgroup

# Try something cool if you have docker installed
docker run -it ubuntu cat /proc/energy/cgroup

# Unload when done
$ sudo make uninstall
```


## Running Inside Virtual Machines

Many cloud or desktop hypervisors disable the vPMU by default, which prevents the **instruction counter** from being active inside guests.

Check current state:
```bash
$ cat /sys/module/kvm/parameters/enable_pmu
N
```

If it prints `N`, enable it **on the host** (all VMs must be shut down first):
```bash
# Intel host
sudo modprobe -r kvm_intel
sudo modprobe   kvm_intel enable_pmu=1

# AMD host
sudo modprobe -r kvm_amd
sudo modprobe   kvm_amd enable_pmu=1
```
To make it persistent:
```bash
echo 'options kvm_intel enable_pmu=1' | sudo tee /etc/modprobe.d/kvm_pmu.conf   # or kvm_amd
```
Within the guest ensure `perf_event_paranoid` allows kernel counters:
```bash
sudo sysctl -w kernel.perf_event_paranoid=-1   # Debugging only!
```

## Sampling Interval & Weighting
### Change interval **at load time**
```bash
sudo insmod energy_proc.ko sample_ns=25000000      # 25 ms
```
### Change **at run time**
```bash
# New value in nanoseconds (5 ms):
echo 5000000 | sudo tee /sys/module/energy_proc/parameters/sample_ns
```

### Adjust individual weights
```bash
# Double the weight of network RX packets
sudo modprobe -r energy_proc
sudo insmod energy_proc.ko w_net_rx_packets=2
```
> Each weight is multiplied by its metric and the sum is exposed as `energy=INT.FRAC` where FRAC has three decimal places (kilo‑scaling).

## Reading the Metrics
* **`/proc/energy/cgroup`** – Metrics for tasks in the caller’s default cgroup (read‑able by unprivileged users).
* **`/proc/energy/all`** – Same as above but **global**; requires `CAP_SYS_ADMIN` (root) to prevent container escapes.
* **`/sys/kernel/debug/energy/all`** – Debugfs variant with extra module state; root only.

A single line looks like:
```text
pid=3187 energy=12.457 alive=1 kernel=0 cpu_ns=285931257 mem=10485760 instructions=8952846 wakeups=14 diski=0 disko=0 rx=22 tx=17 comm=python3
```

Field               | Meaning
--------------------|--------------------------------------------------------
`pid`               | Process ID
`energy`            | Weighted score (kilo‑scaled)
`alive`             | 1 if `pid_alive()` at time of sample
`kernel`            | 1 for kernel threads / kthreads
`cpu_ns`            | Cumulative user+sys CPU time (ns)
`mem`               | Resident Set Size (bytes)
`instructions`      | Retired instructions (if PMU available)
`wakeups`           | Scheduler wake‑ups since process start
`diski`, `disko`    | Bytes read / written by the task
`rx`, `tx`          | Network packets received / transmitted
`comm`              | Task name (`TASK_COMM_LEN`)


## Data Collection Helper
The repository ships with **`energy-logger.sh`** which periodically dumps `/proc/energy/all` to disk for offline analysis (e.g. weight regression).

1. Pick a longer sampling interval to keep file size manageable:
   ```bash
   echo 100000000 > /sys/module/energy_proc/parameters/sample_ns   # 100 ms
   ```
2. Start the collector:
   ```bash
   sudo ./energy-logger.sh
   ```

## Model

We use a linear model to calculate the energy score for each process. You should train this model yourself by

1) `src`
1) running the data collection helper
```
echo 100000000 > /sys/module/energy_proc/parameters/sample_ns
sudo ./energy-logger.sh
```
1) `python3 -m venv venv`
1) `source venv/bin/activate`
1) `pip install -r requirements.txt`
1) `python3 model.py tmp/energy-XXXX.log`

You can then add the weights to your kernel module by 
```bash
echo 1231232 > /sys/module/energy_proc/parameters/PARAM   # 100 ms
```

Please remember that you can not add floats. We use fix decimal values with 3 decimal points. 

## Test

There is a test script you can run that you need to run on a host that will build the kernel extension and then see if everythig works out. Just run
```
sudo ./test.sh
```

## Troubleshooting
| Symptom                                     | Fix |
|---------------------------------------------|-----|
| `insmod: ERROR: could not insert module: Operation not permitted` | Ensure secure boot allows unsigned modules or sign the module. |
| `rapl MSRs not available – energy metrics off` | Running on AMD or RAPL disabled in BIOS.  Energy still computed from other metrics. |
| `perf_event_open: Permission denied` inside VM | Enable PMU passthrough as described above. |
| Null lines or zeros in `/proc/energy/*`      | Sampling interval set too high?  Confirm `iterations` increases in debugfs. |

## Contributing
Patches and 🍻 are welcome! 

You can either contribute here on GitHub or drop me a message under didi@ribalba.de

