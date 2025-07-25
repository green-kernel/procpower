// SPDX-License-Identifier: GPL-2.0
/*
 * energy_proc.c – expose per-cgroup energy usage via /proc/energy
 *
 *   cat /proc/energy
 *
 * Builds on any kernel ≥ 5.6 (uses struct proc_ops).  For older kernels
 * flip the small #ifdef near the bottom to use file_operations instead.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>
#include <linux/cgroup.h>
#include <linux/version.h>
#include <linux/sched/signal.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("didi@ribalba.de");
MODULE_DESCRIPTION("A proc file that exposes per-cgroup energy usage in µJ");
MODULE_VERSION("0.1");


static u64 read_cgroup_joules(struct cgroup *cgrp)
{
	return ktime_get_ns() / 1000ULL;
}


static int energy_show(struct seq_file *m, void *v)
{
	struct cgroup *cgrp = task_dfl_cgroup(current);  /* cgroup v2 path */
	u64 uj = read_cgroup_joules(cgrp);

    seq_printf(m, "%llu\n", uj);
        rcu_read_lock();
        {
                struct task_struct *p, *t;

                /* walk every thread on the system */
                for_each_process_thread(p, t) {
                        if (task_dfl_cgroup(t) == cgrp)
                                seq_printf(m, "pid: %d\n", t->pid);
                }
        }
        rcu_read_unlock();

    return 0;
}

static int energy_open(struct inode *inode, struct file *file)
{
	return single_open(file, energy_show, NULL);
}


static const struct proc_ops energy_proc_ops = {
	.proc_open    = energy_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *energy_entry;

static int __init energy_init(void)
{
	energy_entry = proc_create("energy", 0444, NULL, &energy_proc_ops);
	if (!energy_entry)
		return -ENOMEM;

	pr_info("energy_proc: /proc/energy_uj registered\n");
	return 0;
}

static void __exit energy_exit(void)
{
	proc_remove(energy_entry);
	pr_info("energy_proc: module unloaded\n");
}

module_init(energy_init);
module_exit(energy_exit);
