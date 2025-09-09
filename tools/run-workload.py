import psutil
import subprocess
import argparse
from time import sleep

def run_workload(workload):

    if (utilization := psutil.cpu_percent(1)) > 5:
        raise RuntimeError(f"Your system seems busy. Utilization must be below 5% to run model workloads and training. Is currently {utilization}")

    if workload == 'mixed':
        print('Running Workload: Mixed')
        sleep(40)
        subprocess.check_output(['stress-ng', '--syscall', '1', '-t', '10'])
        subprocess.check_output(['stress-ng', '--syscall', '2', '-t', '10'])
        subprocess.check_output(['stress-ng', '--syscall', '5', '-t', '10'])
        subprocess.check_output(['stress-ng', '--syscall', '10', '-t', '10'])
    elif workload == 'idle':
        print('Running Workload: Idle')
        sleep(40)

    elif workload == 'syscall':
        print('Running Workload: Syscall')

        # TODO - Get max cores
        subprocess.check_output(['stress-ng', '--syscall', '1', '-t', '10'])
        subprocess.check_output(['stress-ng', '--syscall', '2', '-t', '10'])
        subprocess.check_output(['stress-ng', '--syscall', '5', '-t', '10'])
        subprocess.check_output(['stress-ng', '--syscall', '10', '-t', '10'])

    elif workload == 'cpu':
        print('Running Workload: CPU')

        # TODO - Get max cores
        subprocess.check_output(['stress-ng', '-c', '1', '-t', '10'])
        subprocess.check_output(['stress-ng', '-c', '2', '-t', '10'])
        subprocess.check_output(['stress-ng', '-c', '5', '-t', '10'])
        subprocess.check_output(['stress-ng', '-c', '10', '-t', '10'])

    elif workload == 'memory':
        print('Running Workload: Memory')

        # TODO - Get max cores
        subprocess.check_output(['stress-ng', '-m', '1', '-t', '10'])
        subprocess.check_output(['stress-ng', '-m', '2', '-t', '10'])
        subprocess.check_output(['stress-ng', '-m', '5', '-t', '10'])
        subprocess.check_output(['stress-ng', '-m', '10', '-t', '10'])
    else:
        raise ValueError(f"Workload {workload} is not known. Maybe a typo?")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Run a workload on system to create an energy model for")
    parser.add_argument("workload",
        choices=['idle', 'cpu', 'syscall', 'memory', 'mixed'],
        help='Select a workload to train the model on'
    )
    args = parser.parse_args()

    run_workload(args.workload)