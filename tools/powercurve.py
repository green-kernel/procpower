import os
import subprocess
import time
import argparse
import pandas as pd
import psutil
import plotext as plt

def read_energy(cmd):
    return int(subprocess.check_output(cmd.split()).decode().strip())

def run_stress(load_percent, cores, step_duration):
    return subprocess.check_output([
        "stress-ng",
        "--cpu", str(cores),
        "--cpu-load", str(load_percent),
        "--cpu-method", "int64double",
        "--timeout", f"{step_duration}s"
    ], stderr=subprocess.DEVNULL)

def validate_name(path, name):
    ps = subprocess.run(['cat', path], check=False, stdout=subprocess.PIPE, encoding='UTF-8')
    if ps.stdout.strip() != name:
        raise ValueError(f"{path} was != {name} but {ps.stdout}")

def main():
    parser = argparse.ArgumentParser(description="CPU stress & RAPL measurement")
    parser.add_argument("--cores", type=int, help="Number of CPU cores to stress")
    parser.add_argument("--step-duration", type=int, default=10, help="Duration per step in seconds")
    parser.add_argument("--power-source", type=str, choices=['rapl_psys', 'rapl_package', 'mcp'], help="Specify the source to be used for the power reading", required=True)
    args = parser.parse_args()

    cores = args.cores or psutil.cpu_count(logical=True)
    step_duration = args.step_duration 

    if args.power_source == 'rapl_package':
        validate_name('/sys/devices/virtual/powercap/intel-rapl/intel-rapl:0/name', 'package-0')
        cmd = "sudo cat /sys/devices/virtual/powercap/intel-rapl/intel-rapl:0/energy_uj"
        energy_unit = 'uJ'
    elif args.power_source == 'rapl_psys':
        validate_name('/sys/devices/virtual/powercap/intel-rapl/intel-rapl:1/name', 'psys')
        cmd = "sudo cat /sys/devices/virtual/powercap/intel-rapl/intel-rapl:1/energy_uj"
        energy_unit = 'uJ'
    elif args.power_source == 'mcp':
        cmd = os.path.expanduser("~/green-metrics-tool/metric_providers/psu/energy/ac/mcp/machine/metric-provider-binary -e -o")
        energy_unit = 'Ws'


    print(f"Using {cores} cores with step duration {step_duration} s")

    results = []

    for load in range(0, 110, 10):
        print(f"Running load: {load}%")

        e_start = read_energy(cmd)
        t_start = time.time()

        run_stress(load, cores, step_duration)

        t_end = time.time()
        e_end = read_energy(cmd)

        energy = e_end - e_start
        duration = t_end - t_start
        if energy_unit == 'uJ':
            power_w = (energy / 1e6) / duration
        elif energy_unit == 'Ws':
            power_w = energy / duration

        results.append({
            "cpu_load": load,
            "energy": energy,
            "energy_unit": energy_unit,
            "duration_s": duration,
            "power_w": power_w
        })

    df = pd.DataFrame(results)
    print(df)


    x = df["cpu_load"].tolist()
    y = df["power_w"].tolist()

    plt.clear_data()
    plt.plot(x, y, marker='dot')
    plt.title("CPU Load vs Power (ASCII)")
    plt.xlabel("CPU Load (%)")
    plt.ylabel("Power (W)")
    plt.show()

if __name__ == "__main__":
    main()