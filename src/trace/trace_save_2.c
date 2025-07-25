// SPDX-License-Identifier: GPL-2.0
/*
 * pidmetrics.c — per-PID metrics sampler (10 ms) – Linux ≥ 5.10 and 6.8-current
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/tracepoint.h>
#include <trace/events/net.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/perf_event.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/version.h>

#define DRV_NAME         "energy_proc"

static unsigned long long sample_ns = 10ULL * NSEC_PER_MSEC;
module_param(sample_ns, ullong, 0644);
MODULE_PARM_DESC(sample_ns, "Sampling period in nanoseconds (default: 10 ms = 10 000 000 ns)");

static bool collect_stats = false;
module_param(collect_stats, bool, 0644);
MODULE_PARM_DESC(collect_stats, "Triggers the collection of statistics for the model in /sys/kernel/debug/energy_proc_dump");


static bool pmu_supported = true;

atomic64_t              trace_calls;

struct pid_metrics {
	u32                     pid;
	int                     alive;
	u64                     cpu_ns;
	u64                     instructions;
	u64                     wakeups;
	atomic64_t              net_rx_packets; // We make these atomic as they can be updated from multiple contexts
	atomic64_t              net_tx_packets; // We make these atomic as they can be updated from multiple contexts
	u64                     disk_read_bytes;
	u64                     disk_write_bytes;
	u64                     mem_bytes;
    bool                    is_kernel;
	char                    comm[TASK_COMM_LEN];

	/* internals ---------------------------------------------------- */
	struct rhash_head       node;
	unsigned long           last_seen;   /* jiffies */
	struct perf_event      *insn_evt;

};

static const struct rhashtable_params ht_params = {
	.key_len            = sizeof(u32),
	.key_offset         = offsetof(struct pid_metrics, pid),
	.head_offset        = offsetof(struct pid_metrics, node),
	.automatic_shrinking= true,
	.nelem_hint         = 1024,
};


static struct rhashtable     pid_ht;
static struct hrtimer        sampler;
static struct kmem_cache    *pm_cache;
//static struct dentry        *dbg_file;
static struct dentry *dir;
static struct tracepoint *tp_tx;
static struct tracepoint *tp_rx;

static void pm_tp_tx(void *data, struct sk_buff *skb);
static void pm_tp_rx(void *data, struct sock *sk, struct msghdr *msg, size_t len, int flags);

/* ----------------------------------END VARS---------------------------------------- */


static bool pid_still_alive(u32 pid)
{
        bool alive = false;
        rcu_read_lock();
        {
                struct task_struct *p = pid_task(find_vpid(pid), PIDTYPE_PID);
                alive = p && pid_alive(p);
        }
        rcu_read_unlock();
        return alive;
}

/* --------------------------------------------------------------------------
                          starup checks
-------------------------------------------------------------------------- */


/* --------------------------------------------------------------------------
                          starup checks
-------------------------------------------------------------------------- */

static void detect_pmu(void)
{
        struct perf_event_attr attr = {
                .type       = PERF_TYPE_HARDWARE,
                .config     = PERF_COUNT_HW_INSTRUCTIONS,
                .size       = sizeof(attr),
                .disabled   = 1,
                .exclude_hv = 1,
        };
        struct perf_event *evt;

        evt = perf_event_create_kernel_counter(&attr, -1, current, NULL, NULL);
        if (IS_ERR(evt)) {
                long err = PTR_ERR(evt);
                if (err == -EOPNOTSUPP || err == -ENODEV) {
                        pr_warn_once(DRV_NAME ": hardware PMU not present (%ld) – instructions metric disabled. You might be in a VM.\n", err);
                } else {
                        pr_warn_once(DRV_NAME ": unexpected perf error %ld – instructions metric disabled. You might be in a VM.\n", err);
                }
				pmu_supported = false;
        } else {
                perf_event_release_kernel(evt);
        }
}

/* -------------------------------------------------------------------------- */
/*                          network probres	                                  */
static void find_net_dev_queue_tracepoint(struct tracepoint *tp, void *priv)
{
    if (strcmp(tp->name, "net_dev_queue") == 0)
        *(struct tracepoint **)priv = tp;

}
static void find_sock_recvmsg_tracepoint(struct tracepoint *tp, void *priv)
{
    if (strcmp(tp->name, "sock_recvmsg") == 0)
        *(struct tracepoint **)priv = tp;

}
static int pm_register_tracepoints(void)
{
		for_each_kernel_tracepoint(find_net_dev_queue_tracepoint, &tp_tx);
		for_each_kernel_tracepoint(find_sock_recvmsg_tracepoint, &tp_rx);

        if (!tp_tx || !tp_rx)
                return -ENOENT;

        tracepoint_probe_register(tp_tx, pm_tp_tx, NULL);
        tracepoint_probe_register(tp_rx, (void *)pm_tp_rx, NULL);
        return 0;
}

static void pm_unregister_tracepoints(void)
{
        if (tp_tx)
                tracepoint_probe_unregister(tp_tx, pm_tp_tx, NULL);
        if (tp_rx)
                tracepoint_probe_unregister(tp_rx, (void *)pm_tp_rx, NULL);
        tracepoint_synchronize_unregister();
}

static void pm_tp_tx(void *data, struct sk_buff *skb)
{
        struct pid_metrics *pm;
        u32 pid = task_pid_nr(current);

        // ADDED: RCU read lock is required for rhashtable_lookup_fast.
        rcu_read_lock();
        pm = rhashtable_lookup_fast(&pid_ht, &pid, ht_params);
        if (pm)
                atomic64_inc(&pm->net_tx_packets);
        rcu_read_unlock();
}

static void pm_tp_rx(void *data, struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
    struct pid_metrics *pm;
    u32 pid;

    pid = task_pid_nr(current);
    if (pid == 0)
        return;

    // ADDED: RCU read lock is required for rhashtable_lookup_fast.
    rcu_read_lock();
    pm = rhashtable_lookup_fast(&pid_ht, &pid, ht_params);
    if (pm)
        atomic64_inc(&pm->net_rx_packets);
    rcu_read_unlock();
}
/* -------------------------------------------------------------------------- */
/*                          sampling timer callback                           */

static enum hrtimer_restart sample_fn(struct hrtimer *t)
{
	struct task_struct *p;

	rcu_read_lock();

	for_each_process(p) {
		struct pid_metrics *pm;
		u32 pid = task_pid_nr(p);

		pm = rhashtable_lookup_fast(&pid_ht, &pid, ht_params);
		if (!pm) {
			pm = kmem_cache_zalloc(pm_cache, GFP_ATOMIC);
			if (!pm)
				continue;
			pm->pid = pid;
			get_task_comm(pm->comm, p);
			if (rhashtable_insert_fast(&pid_ht, &pm->node, ht_params)) {
				kmem_cache_free(pm_cache, pm);
				continue;
			}

			if(pmu_supported){
				struct perf_event_attr attr = {
					.type           = PERF_TYPE_HARDWARE,
					.config         = PERF_COUNT_HW_INSTRUCTIONS,
					.size           = sizeof(attr),
					.disabled       = 1,
					.exclude_hv     = 1,
					.inherit        = 1,
				};

				pm->insn_evt = perf_event_create_kernel_counter(&attr, -1, p, NULL, NULL);
				if (IS_ERR(pm->insn_evt)) {
						pr_warn_once("pidmetrics: instr event for %s[%u] failed (%ld)\n", pm->comm, pid, PTR_ERR(pm->insn_evt));
						pm->insn_evt = NULL;
				} else {
						perf_event_enable(pm->insn_evt);
				}
			}

			// Threads can not change between kernel and user space, so we can set this once
			pm->is_kernel = (p->flags & PF_KTHREAD) || !p->mm;

		}

		/* -------- actual metrics -------------------------------------- */
		pm->alive     = pid_alive(p); // This will be 1 in 99.99% of cases
		pm->last_seen = jiffies;

		pm->cpu_ns = p->se.sum_exec_runtime;

		if (pmu_supported && pm->insn_evt)
			pm->instructions = perf_event_read_value(pm->insn_evt, NULL, NULL);

		pm->wakeups = p->stats.nr_wakeups;

		pm->disk_read_bytes  = p->ioac.read_bytes;
		pm->disk_write_bytes = p->ioac.write_bytes;

		if (p->mm)
			pm->mem_bytes = get_mm_rss(p->mm) << PAGE_SHIFT;
		else
			pm->mem_bytes = 0;
	}

	rcu_read_unlock();

	/* -------- evict dead PIDs ----------------------------------------- */
	{
		struct rhashtable_iter iter;
		struct pid_metrics *pm;

		rhashtable_walk_enter(&pid_ht, &iter);
		rhashtable_walk_start(&iter);
		while ((pm = rhashtable_walk_next(&iter)) && !IS_ERR(pm)) {
			if (!pid_still_alive(pm->pid)) {
				//rhashtable_remove_fast(&pid_ht, &pm->node, ht_params); // For some reason this segfaults and pulls the kernel down
				pm->alive = 0;
				if (pmu_supported && pm->insn_evt)
					perf_event_release_kernel(pm->insn_evt);
				//kmem_cache_free(pm_cache, pm); // Or this pulls the kernel down for some reason
			}
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
	}

	hrtimer_forward_now(t, ns_to_ktime(sample_ns));
	return HRTIMER_RESTART;
}

static int cnt_show(struct seq_file *m, void *v)
{

	struct pid_metrics *entry;
    struct rhashtable_iter iter;

    rhashtable_walk_enter(&pid_ht, &iter);
    rhashtable_walk_start(&iter);

	while ((entry = rhashtable_walk_next(&iter))) {
		if (IS_ERR(entry)) {
			if (PTR_ERR(entry) == -EAGAIN)
				continue;
			break;
		}

		// seq_printf(m,
		// 		"pid=%u alive=%d is_kernel=%d cpu_ns=%llu mem_byte=%llu ",
		// 		entry->pid,
		// 		entry->alive,
		// 		entry->is_kernel,
		// 		entry->cpu_ns,
		// 		entry->mem_bytes);

		// if (pmu_supported)
		// 		seq_printf(m, "instructions=%llu ", entry->instructions);

		// seq_printf(m,
		// 		"wakeups=%llu diski=%llu disko=%llu rx=%lld tx=%lld comm=%s\n",
		// 		entry->wakeups,
		// 		entry->disk_read_bytes,
		// 		entry->disk_write_bytes,
		// 		atomic64_read(&entry->net_rx_packets),
		// 		atomic64_read(&entry->net_tx_packets),
		// 		entry->comm);

	}
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

	seq_printf(m,"trace=%lld\n", atomic64_read(&trace_calls));

    return 0;
}

static int cnt_open(struct inode *inode, struct file *file)
{
    return single_open(file, cnt_show, NULL);
}

static const struct file_operations cnt_fops = {
    .owner   = THIS_MODULE,
    .open    = cnt_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};


/* -------------------------------------------------------------------------- */
/*                    rhashtable destruction helper                           */

static void pm_free(void *ptr, void *arg)
{
	struct pid_metrics *pm = ptr;

	if (pm->insn_evt)
		perf_event_release_kernel(pm->insn_evt);
	kmem_cache_free(pm_cache, pm);
}

/* -------------------------------------------------------------------------- */
/*                          module init / exit                                */

static int __init pidmetrics_init(void)
{
	int ret;
	pr_info(DRV_NAME ": Welcome to the kernel module. Thank you for trying this out. We are loading ...\n");
	// Do the system checks
	detect_pmu();


	pm_cache = KMEM_CACHE(pid_metrics, SLAB_HWCACHE_ALIGN | SLAB_PANIC);

	ret = rhashtable_init(&pid_ht, &ht_params);
	if (ret)
		return ret;

    ret = pm_register_tracepoints();
    if (ret) {
        goto destroy_ht;
    }

	dir = debugfs_create_dir("energy", NULL);
	if (!dir) {
		pr_err("sched_switch_counter: failed to create debugfs dir\n");
		ret = -ENOMEM;
		goto destroy_ht;
	}

	if (!debugfs_create_file("switch", 0444, dir, NULL, &cnt_fops)) {
		pr_err("sched_switch_counter: failed to create debugfs file\n");
		ret = -ENOMEM;
		goto err_debugfs;
	}

	hrtimer_init(&sampler, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
	sampler.function = sample_fn;
	hrtimer_start(&sampler, ns_to_ktime(sample_ns), HRTIMER_MODE_REL_PINNED);

	pr_info(DRV_NAME ": Sampling every %llu ms.\n", sample_ns);
	return 0;

err_debugfs:
	debugfs_remove_recursive(dir);
destroy_ht:
    rhashtable_destroy(&pid_ht);
	return ret;
}

static void __exit pidmetrics_exit(void)
{
	hrtimer_cancel(&sampler);
    debugfs_remove_recursive(dir);
	pm_unregister_tracepoints();
	rhashtable_free_and_destroy(&pid_ht, pm_free, NULL);
	kmem_cache_destroy(pm_cache);
	pr_info(DRV_NAME ": ByBy and thanks for all the fish\n");
}

module_init(pidmetrics_init);
module_exit(pidmetrics_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Didi Hoffmann");
MODULE_DESCRIPTION("WORLD DOMINATION");
