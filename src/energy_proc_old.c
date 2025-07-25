// SPDX-License-Identifier: GPL-2.0
/*
 * energy_proc_kprobe.c – expose per-cgroup “energy-style” metrics via /proc/energy
 *
 *   $ make -C /lib/modules/$(uname -r)/build M=$PWD modules
 *   # insmod energy_proc_kprobe.ko
 *   $ cat /proc/energy
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cgroup.h>
#include <linux/kernfs.h>   /* struct kernfs_node */
#include <linux/pid.h>      /* find_vpid / pid_task */
#include <linux/sched/signal.h>

#include <linux/kprobes.h>
#include <linux/ktime.h>

#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/blk-mq.h>

#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/rhashtable.h>
#include <linux/spinlock.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("didi@ribalba.de");
MODULE_DESCRIPTION("Shows you your energy consumption in /proc/energy");
MODULE_VERSION("0.1");

struct proc_dir_entry *energy_dir, *cgroup_file;


/* ────────────────────────────── version-portable helpers ────────────────── */

/* request direction */
static __always_inline bool rq_is_read_portable(const struct request *rq)
{
	return rq_data_dir(rq) == READ;
}
static __always_inline bool rq_is_write_portable(const struct request *rq)
{
	return rq_data_dir(rq) == WRITE;
}

/* request size */
static __always_inline unsigned int rq_bytes_portable(const struct request *rq)
{
#if defined(blk_rq_bytes)
	return blk_rq_bytes(rq);
#elif defined(blk_rq_payload_bytes)
	return blk_rq_payload_bytes(rq);
#else
	return blk_rq_sectors(rq) << 9;      /* sectors × 512 bytes */
#endif
}

/* Some very new kernels removed CGROUP_NAME_LEN; define if missing. */
#ifndef CGROUP_NAME_LEN
#define CGROUP_NAME_LEN 128
#endif

/* ───────────────────────────── data structures ─────────────────────────── */

struct pid_metrics {
	u32                     pid;
	u64                     cpu_ns;
	u64                     wakeups;
	u64                     net_rx_packets;
	u64                     net_tx_packets;
	u64                     disk_read_bytes;
	u64                     disk_write_bytes;
	u64                     mem_bytes;

	u64                     last_start_ns;      /* 0 ⇒ not running    */
	struct rhash_head       node;
	char                    comm[TASK_COMM_LEN];
};

static const struct rhashtable_params ht_params = {
	.key_len        = sizeof(u32),
	.key_offset     = offsetof(struct pid_metrics, pid),
	.head_offset    = offsetof(struct pid_metrics, node),
	.automatic_shrinking = true,
};

static struct rhashtable pid_ht;
static DEFINE_SPINLOCK(pid_ht_lock);

/* per-CPU idle */
struct idle_cpu {
	u64 idle_start_ns;
	u64 idle_total_ns;
};
static DEFINE_PER_CPU(struct idle_cpu, idle_info);

/* ─────────────────────────── helper: PID → metrics ─────────────────────── */

static struct pid_metrics *lookup_or_create_pid(u32 pid, const char *comm)
{
	struct pid_metrics *m;

	rcu_read_lock();
	m = rhashtable_lookup(&pid_ht, &pid, ht_params);
	rcu_read_unlock();
	if (m)
		return m;

	m = kzalloc(sizeof(*m), GFP_ATOMIC);
	if (!m)
		return NULL;

	m->pid = pid;
	strscpy(m->comm, comm ? comm : "<unknown>", TASK_COMM_LEN);

	spin_lock(&pid_ht_lock);
	if (rhashtable_lookup_fast(&pid_ht, &pid, ht_params)) {
		kfree(m);
		m = rhashtable_lookup_fast(&pid_ht, &pid, ht_params);
	} else if (rhashtable_insert_fast(&pid_ht, &m->node, ht_params)) {
		kfree(m);
		m = NULL;
	}
	spin_unlock(&pid_ht_lock);
	return m;
}

/* ───────────────────────────── kprobe handlers ─────────────────────────── */

/* sched:sched_switch → finish_task_switch (PRE) */
static int kp_finish_task_switch_pre(struct kprobe *kp, struct pt_regs *regs)
{
	u64 ts = ktime_get_ns();
	struct task_struct *prev = (struct task_struct *)regs->si;
	struct task_struct *next = current;

	if (prev->pid) {
		struct pid_metrics *m = lookup_or_create_pid(prev->pid, prev->comm);
		if (m && m->last_start_ns) {
			m->cpu_ns += ts - m->last_start_ns;
			m->last_start_ns = 0;
		}
	}
	if (next->pid) {
		struct pid_metrics *m = lookup_or_create_pid(next->pid, next->comm);
		if (m) {
			m->last_start_ns = ts;
			m->wakeups++;
			if (!(next->flags & PF_KTHREAD) && next->mm)
				m->mem_bytes = (u64)next->mm->total_vm << PAGE_SHIFT;
		}
	}
	return 0;
}

/* cpuidle_enter_state – entry/exit (kretprobe) */
// static int krp_cpuidle_entry(struct kretprobe_instance *ri, struct pt_regs *r)
// {
// 	this_cpu_ptr(&idle_info)->idle_start_ns = ktime_get_ns();
// 	return 0;
// }
// static int krp_cpuidle_exit(struct kretprobe_instance *ri, struct pt_regs *r)
// {
// 	struct idle_cpu *ic = this_cpu_ptr(&idle_info);
// 	if (ic->idle_start_ns) {
// 		ic->idle_total_ns += ktime_get_ns() - ic->idle_start_ns;
// 		ic->idle_start_ns = 0;
// 	}
// 	return 0;
// }


/* ─────────────────────────── /proc/energy ─────────────────────────────── */

static struct proc_dir_entry *energy_entry;

/* avoid non-exported kernfs_name() */
static void cg_get_name(struct cgroup *cg, char *buf, size_t len)
{
	struct kernfs_node *kn = READ_ONCE(cg->kn);
	if (kn && kn->name)
		strscpy(buf, kn->name, len);
	else
		strscpy(buf, "?", len);
}

static int energy_show(struct seq_file *m, void *v)
{
	struct cgroup *cg_self = task_dfl_cgroup(current);
	char cgname[CGROUP_NAME_LEN];
	u64 uj = ktime_get_ns() / 1000ULL;
	unsigned int cpu;

	cg_get_name(cg_self, cgname, sizeof(cgname));
	seq_printf(m, "cgroup: %s energy_uj=%llu\n", cgname, uj);

	rcu_read_lock();
	{
		struct rhashtable_iter iter;
		rhashtable_walk_enter(&pid_ht, &iter);
		rhashtable_walk_start(&iter);
		for (;;) {
			struct pid_metrics *p = rhashtable_walk_next(&iter);
			if (p == ERR_PTR(-EAGAIN))
				continue;
			if (IS_ERR(p))
				break;

			struct task_struct *t =
				pid_task(find_vpid(p->pid), PIDTYPE_PID);
			if (!t || task_dfl_cgroup(t) != cg_self)
				continue;

			seq_printf(m,
				"pid=%u comm=%s cpu_ns=%llu wakeups=%llu "
				"net_rx=%llu net_tx=%llu "
				"rd=%llu wr=%llu mem=%llu\n",
				p->pid, p->comm,
				p->cpu_ns, p->wakeups,
				p->net_rx_packets, p->net_tx_packets,
				p->disk_read_bytes, p->disk_write_bytes,
				p->mem_bytes);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
	}
	rcu_read_unlock();

	for_each_possible_cpu(cpu) {
		struct idle_cpu *ic = &per_cpu(idle_info, cpu);
		seq_printf(m, "cpu%d_idle_ns=%llu\n", cpu, ic->idle_total_ns);
	}
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

/* ───────────────────── probe objects & module boiler-plate ─────────────── */

static struct kprobe kp_finish_task_switch = {
	.symbol_name = "finish_task_switch",
	.pre_handler = kp_finish_task_switch_pre,
};



static int __init energy_init(void)
{
	int err;

	if ((err = rhashtable_init(&pid_ht, &ht_params)))
		return err;

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
	
	if ((err = register_kprobe(&kp_finish_task_switch)))
		goto out_unreg;

	pr_info("energy_proc_kprobe: loaded\n");
	return 0;

out_unreg:
	unregister_kprobe(&kp_finish_task_switch);
	remove_proc_entry("cgroup", energy_dir);
	remove_proc_entry("energy", NULL);
	rhashtable_destroy(&pid_ht);
	return err;
}

static void __exit energy_exit(void)
{
	proc_remove(energy_entry);
	remove_proc_entry("cgroup", energy_dir);
	remove_proc_entry("energy", NULL);

	unregister_kprobe(&kp_finish_task_switch);
	rhashtable_destroy(&pid_ht);
	pr_info("energy_proc_kprobe: unloaded\n");
}

module_init(energy_init);
module_exit(energy_exit);
