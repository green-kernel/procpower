// SPDX-License-Identifier: AGPL
/*
 * energy_proc.c – expose per-cgroup energy usage via /proc/energy
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>
#include <linux/cgroup.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <trace/events/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("didi@ribalba.de");
MODULE_DESCRIPTION("A proc file that exposes per-cgroup energy usage in µJ");
MODULE_VERSION("0.1");

#ifndef CGROUP_NAME_LEN
#define CGROUP_NAME_LEN 128
#endif



/* ------------------------------ PROBE  ------------------------------ */


/// ------------------------------ MODEL ------------------------------
static u64 read_cgroup_joules(struct cgroup *cgrp){
	return ktime_get_ns() / 1000ULL;
}

/// ------------------------------ PROC OUTPUT ------------------------------

static void cg_get_name(struct cgroup *cg, char *buf, size_t len)
{
	struct kernfs_node *kn = READ_ONCE(cg->kn);
	if (kn && kn->name)
		strscpy(buf, kn->name, len);
	else
		strscpy(buf, "?", len);
}


static int energy_show(struct seq_file *m, void *v){
	struct cgroup *cgrp = task_dfl_cgroup(current);  /* cgroup v2 path */
	u64 total_uj = read_cgroup_joules(cgrp);

	char cgname[CGROUP_NAME_LEN];

	cg_get_name(cgrp, cgname, sizeof(cgname));
	seq_printf(m, "cgroup: %s\n", cgname);

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
	seq_printf(m, "total energy_uj:%llu\n", total_uj);

    return 0;
}

static int energy_open(struct inode *inode, struct file *file){
	return single_open(file, energy_show, NULL);
}

/* ------------------------------ structs  ------------------------------ */


static const struct proc_ops energy_proc_ops = {
	.proc_open    = energy_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};


/// ------------------------------ KERNEL SETUP ------------------------------


static int __init energy_init(void){
	


	energy_dir = proc_mkdir("energy", NULL);
	if (!energy_dir) {
		rhashtable_destroy(&pid_ht);
		return -ENOMEM;
	}

	cgroup_file = proc_create("cgroup", 0444, energy_dir, &energy_proc_ops);  // Create /proc/energy/cgroup
	if (!cgroup_file) {
		remove_proc_entry("energy", NULL);  // Clean up the directory
		rhashtable_destroy(&pid_ht);
		return -ENOMEM;
	}

	pr_info("energy_proc: module registered\n");
	return 0;
}


static void __exit energy_exit(void)
{
        /* 1.  Remove dynamic instrumentation first */
        unregister_trace_sched_switch(probe_sched_switch, NULL);
		tracepoint_synchronize_unregister();

        /* 2.  Make sure no one is still running in the probe */
        synchronize_rcu();          /* or synchronize_sched() */

        /* 3.  Tear the data structures down */
        rhashtable_destroy(&pid_ht);

        /* 4.  Remove user-visible interfaces last */
        proc_remove(cgroup_file);
        proc_remove(energy_dir);

        pr_info("energy_proc: module unloaded\n");
}

module_init(energy_init);
module_exit(energy_exit);
