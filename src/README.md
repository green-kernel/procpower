## Instructions in virtualised environments

Normally vPMU which we need to get the instruction count if we are virtualised is disabaled. You can check with
```
# cat /sys/module/kvm/parameters/enable_pmu
```

If this outputs N and you want to enable instruction counting in the guests you can do

1) Shutdown all VMs
2)
```
# Intel
sudo modprobe -r kvm_intel
sudo modprobe kvm_intel enable_pmu=1

# AMD
sudo modprobe -r kvm_amd
sudo modprobe kvm_amd enable_pmu=1
```

To make it permanent
```
# vim /etc/modprobe.d/kvm_pmu.conf
options kvm_intel enable_pmu=1        # or: options kvm_amd enable_pmu=1
```

Somtimes it also helps to look at `perf stat` in the guest to see if you can find any error messages.
For debugging you can run `sudo sysctl -w kernel.perf_event_paranoid=-1` to get some values. Not something for production environments!


## Change sampling interval

Be aware that the smaller you make this interval the more overhead you introduce. Also you don't really gain a lot execpt that you record very short lived processes.

# load with a 25 ms period
modprobe energy_proc sample_ns=25000000

# check current value (ns)
cat /sys/module/energy_proc/parameters/sample_ns

# change to 5 ms on the fly (as root)
echo 5000000 > /sys/module/energy_proc/parameters/sample_ns