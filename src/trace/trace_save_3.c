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
#include <linux/relay.h>
#include <linux/kprobes.h>
#include <linux/seq_buf.h>

#define DRV_NAME "energy_proc"
#define PM_LINE_MAX 256

/* Please read the readme.md to see who to set these paramters. You can also change them while the module is leaded */

static unsigned long long sample_ns = 10ULL * NSEC_PER_MSEC;
module_param(sample_ns, ullong, 0644);
MODULE_PARM_DESC(sample_ns, "Sampling period in nanoseconds (default: 10 ms = 10 000 000 ns)");

static bool collect_stats = false;
module_param(collect_stats, bool, 0644);
MODULE_PARM_DESC(collect_stats, "Triggers the collection of statistics for the model in /sys/kernel/debug/energy_proc_dump");

static bool pmu_supported = true;

atomic64_t trace_calls;

struct pid_metrics
{
	u32 pid;
	int alive;
	u64 cpu_ns;
	u64 instructions;
	u64 wakeups;
	atomic64_t net_rx_packets; // We make these atomic as they can be updated from multiple contexts
	atomic64_t net_tx_packets; // We make these atomic as they can be updated from multiple contexts
	u64 disk_read_bytes;
	u64 disk_write_bytes;
	u64 mem_bytes;
	bool is_kernel;
	char comm[TASK_COMM_LEN];

	/* internals ---------------------------------------------------- */
	struct rhash_head node;
	unsigned long last_seen; /* jiffies */
	struct perf_event *insn_evt;
	struct rcu_head rcu;
};

static const struct rhashtable_params ht_params = {
	.key_len = sizeof(u32),
	.key_offset = offsetof(struct pid_metrics, pid),
	.head_offset = offsetof(struct pid_metrics, node),
	.automatic_shrinking = true,
	.nelem_hint = 1024,
};

struct recvmsg_info
{
	size_t len;
};

static struct rhashtable pid_ht;
static struct hrtimer sampler;
static struct kmem_cache *pm_cache;
// static struct dentry        *dbg_file;
static struct dentry *dir;
static struct tracepoint *tp_tx;
static struct kretprobe kr_sock_recvmsg;

static struct rchan *chan;


static void pm_tp_tx(void *data, struct sk_buff *skb);
struct recvmsg_info;

static int kp_sock_recvmsg_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
static int kp_sock_recvmsg_ret(struct kretprobe_instance *ri, struct pt_regs *regs);
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
						  dump output stuff to /sys/kernel/debug/energy_proc_dump
-------------------------------------------------------------------------- */

static int relay_subbuf_start_callback(struct rchan_buf *buf, void *subbuf, void *prev_subbuf, size_t prev_padding)
{
	return 0;
}

static const struct rchan_callbacks relay_cb = {
	.subbuf_start = relay_subbuf_start_callback,
};

static void setup_relay(void)
{
	chan = relay_open("energy_proc_dump", NULL, 1 << 20, 4, &relay_cb, NULL);
	if (!chan)
		pr_err("relay_open failed\n");
}

static inline void log_record(struct pid_metrics *pm)
{
	/* Pre-allocate a scratch buffer on the stack */
	char line[PM_LINE_MAX];
	size_t len;

	/* Nanosecond-resolution timestamp (monotonic) */
	u64 now_ns = ktime_get_ns();

	/*
	 * seq_buf is safer than plain scnprintf() because it
	 * automatically caps writes at the buffer size.
	 */
	struct seq_buf s;
	seq_buf_init(&s, line, sizeof(line));

	seq_buf_printf(&s,
				   "%llu "
				   "pid=%u alive=%d kernel=%d "
				   "cpu_ns=%llu instr=%llu wakeups=%llu "
				   "disk_read=%llu disk_write=%llu "
				   "mem=%llu rx=%lld tx=%lld comm=%s\n",
				   (unsigned long long)now_ns,
				   pm->pid,
				   pm->alive,
				   pm->is_kernel,
				   (unsigned long long)pm->cpu_ns,
				   (unsigned long long)pm->instructions,
				   (unsigned long long)pm->wakeups,
				   (unsigned long long)pm->disk_read_bytes,
				   (unsigned long long)pm->disk_write_bytes,
				   (unsigned long long)pm->mem_bytes,
				   atomic64_read(&pm->net_rx_packets),
				   atomic64_read(&pm->net_tx_packets),
				   pm->comm);

	len = seq_buf_used(&s); /* how many bytes we produced */

	/* Relay it (guaranteed non-blocking, per-CPU) */
	relay_write(chan, line, len);
}
/* --------------------------------------------------------------------------
						  starup checks
-------------------------------------------------------------------------- */

static void detect_pmu(void)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_INSTRUCTIONS,
		.size = sizeof(attr),
		.disabled = 1,
		.exclude_hv = 1,
	};
	struct perf_event *evt;

	evt = perf_event_create_kernel_counter(&attr, -1, current, NULL, NULL);
	if (IS_ERR(evt))
	{
		long err = PTR_ERR(evt);
		if (err == -EOPNOTSUPP || err == -ENODEV)
		{
			pr_warn_once(DRV_NAME ": hardware PMU not present (%ld) – instructions metric disabled. You might be in a VM.\n", err);
		}
		else
		{
			pr_warn_once(DRV_NAME ": unexpected perf error %ld – instructions metric disabled. You might be in a VM.\n", err);
		}
		pmu_supported = false;
	}
	else
	{
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

static int pm_register_tracepoints(void)
{

	int err;

	for_each_kernel_tracepoint(find_net_dev_queue_tracepoint, &tp_tx);
	if (!tp_tx)
		return -ENOENT;

	tracepoint_probe_register(tp_tx, pm_tp_tx, NULL);


	/* -------- RX kretprobe --------------------------------------- */
	kr_sock_recvmsg.kp.symbol_name = "sock_recvmsg";
	kr_sock_recvmsg.entry_handler = kp_sock_recvmsg_entry;
	kr_sock_recvmsg.handler = kp_sock_recvmsg_ret;
	kr_sock_recvmsg.data_size = sizeof(struct recvmsg_info);
	kr_sock_recvmsg.maxactive = 64; /* concurrent executions */

	if ((err = register_kretprobe(&kr_sock_recvmsg)))
	{
		tracepoint_probe_unregister(tp_tx, pm_tp_tx, NULL);
		return err;
	}

	return 0;
}

static void pm_unregister_tracepoints(void)
{
	unregister_kretprobe(&kr_sock_recvmsg);

	if (tp_tx)
		tracepoint_probe_unregister(tp_tx, pm_tp_tx, NULL);

	tracepoint_synchronize_unregister();
}

static void pm_tp_tx(void *data, struct sk_buff *skb)
{
	struct pid_metrics *pm;
	u32 pid = task_pid_nr(current);

	rcu_read_lock();
	pm = rhashtable_lookup_fast(&pid_ht, &pid, ht_params);
	if (pm && pm->alive)
		atomic64_inc(&pm->net_tx_packets);
	rcu_read_unlock();
}

/* -------------------------------------------------------------------------- */
/*                     RX: kretprobe on sock_recvmsg()                        */

/* Per-instance scratchpad to carry the len argument from entry → return */

static int kp_sock_recvmsg_entry(struct kretprobe_instance *ri,
								 struct pt_regs *regs)
{
	struct recvmsg_info *info = (void *)ri->data;

	/* x86-64 calling convention: arg #2 (len) is in RDX               */
#ifdef CONFIG_X86_64
	info->len = regs->dx;
#elif defined(CONFIG_ARM64)
	info->len = regs->regs[2];
#else
#error "Add pt_regs accessor for your architecture"
#endif
	return 0;
}

static int kp_sock_recvmsg_ret(struct kretprobe_instance *ri,
							   struct pt_regs *regs)
{
	long ret = regs_return_value(regs); /* bytes copied, 0 = orderly shutdown */
	struct recvmsg_info *info = (void *)ri->data;
	u32 pid;

	if (ret <= 0) /* ignore errors / FIN */
		return 0;

	pid = task_pid_nr(current);

	rcu_read_lock();
	{
		struct pid_metrics *pm =
			rhashtable_lookup_fast(&pid_ht, &pid, ht_params);

		if (pm)
		{
			atomic64_inc(&pm->net_rx_packets); /* count one successful recv */
											   /* If you also want bytes: atomic64_add(ret, &pm->net_rx_bytes); */
		}
	}
	rcu_read_unlock();

	return 0;
}

/* -------------------------------------------------------------------------- */
/*                          sampling timer callback                           */

static void pm_free_rcu(struct rcu_head *head)
{
    struct pid_metrics *pm = container_of(head, struct pid_metrics, rcu);
    if (pm->insn_evt)
        perf_event_release_kernel(pm->insn_evt);
    kmem_cache_free(pm_cache, pm);
}

static enum hrtimer_restart sample_fn(struct hrtimer *t)
{
	struct task_struct *p;

	rcu_read_lock();

	for_each_process(p)
	{
		struct pid_metrics *pm;
		u32 pid = task_pid_nr(p);

		pm = rhashtable_lookup_fast(&pid_ht, &pid, ht_params);
		if (!pm)
		{
			pm = kmem_cache_zalloc(pm_cache, GFP_ATOMIC);
			if (!pm)
				continue;
			pm->pid = pid;
			get_task_comm(pm->comm, p);
			if (rhashtable_insert_fast(&pid_ht, &pm->node, ht_params))
			{
				kmem_cache_free(pm_cache, pm);
				continue;
			}

			if (pmu_supported)
			{
				struct perf_event_attr attr = {
					.type = PERF_TYPE_HARDWARE,
					.config = PERF_COUNT_HW_INSTRUCTIONS,
					.size = sizeof(attr),
					.disabled = 1,
					.exclude_hv = 1,
					.inherit = 1,
				};

				pm->insn_evt = perf_event_create_kernel_counter(&attr, -1, p, NULL, NULL);
				if (IS_ERR(pm->insn_evt))
				{
					pr_warn_once("pidmetrics: instr event for %s[%u] failed (%ld)\n", pm->comm, pid, PTR_ERR(pm->insn_evt));
					pm->insn_evt = NULL;
				}
				else
				{
					perf_event_enable(pm->insn_evt);
				}
			}

			// Threads can not change between kernel and user space, so we can set this once
			pm->is_kernel = (p->flags & PF_KTHREAD) || !p->mm;
		}

		/* -------- actual metrics -------------------------------------- */
		pm->alive = pid_alive(p); // This will be 1 in 99.99% of cases
		pm->last_seen = jiffies;

		pm->cpu_ns = p->se.sum_exec_runtime;

		if (pmu_supported && pm->insn_evt)
			pm->instructions = perf_event_read_value(pm->insn_evt, NULL, NULL);

		pm->wakeups = p->stats.nr_wakeups;

		pm->disk_read_bytes = p->ioac.read_bytes;
		pm->disk_write_bytes = p->ioac.write_bytes;

		if (p->mm)
			pm->mem_bytes = get_mm_rss(p->mm) << PAGE_SHIFT;
		else
			pm->mem_bytes = 0;

		if (collect_stats)
		{
			log_record(pm);
		}
	}

	rcu_read_unlock();

	/* -------- evict dead PIDs ----------------------------------------- */
	{
		struct rhashtable_iter iter;
		struct pid_metrics *pm;

		rhashtable_walk_enter(&pid_ht, &iter);
		rhashtable_walk_start(&iter);
		while ((pm = rhashtable_walk_next(&iter)) && !IS_ERR(pm))
		{
			if (!pid_still_alive(pm->pid))
			{
				// rhashtable_remove_fast(&pid_ht, &pm->node, ht_params); // For some reason this segfaults and pulls the kernel down
				pm->alive = 0;
				call_rcu(&pm->rcu, pm_free_rcu);
				// kmem_cache_free(pm_cache, pm); // Or this pulls the kernel down for some reason
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

	while ((entry = rhashtable_walk_next(&iter)))
	{
		if (IS_ERR(entry))
		{
			if (PTR_ERR(entry) == -EAGAIN)
				continue;
			break;
		}

		seq_printf(m,
				   "pid=%u alive=%d is_kernel=%d cpu_ns=%llu mem_byte=%llu ",
				   entry->pid,
				   entry->alive,
				   entry->is_kernel,
				   entry->cpu_ns,
				   entry->mem_bytes);

		if (pmu_supported)
			seq_printf(m, "instructions=%llu ", entry->instructions);

		seq_printf(m,
				   "wakeups=%llu diski=%llu disko=%llu rx=%lld tx=%lld comm=%s\n",
				   entry->wakeups,
				   entry->disk_read_bytes,
				   entry->disk_write_bytes,
				   atomic64_read(&entry->net_rx_packets),
				   atomic64_read(&entry->net_tx_packets),
				   entry->comm);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	// seq_printf(m,"trace=%lld\n", atomic64_read(&trace_calls));

	return 0;
}

static int cnt_open(struct inode *inode, struct file *file)
{
	return single_open(file, cnt_show, NULL);
}

static const struct file_operations cnt_fops = {
	.owner = THIS_MODULE,
	.open = cnt_open,
	.read = seq_read,
	.llseek = seq_lseek,
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
	if (ret)
	{
		goto destroy_ht;
	}

	dir = debugfs_create_dir("energy", NULL);
	if (!dir)
	{
		pr_err("sched_switch_counter: failed to create debugfs dir\n");
		ret = -ENOMEM;
		goto destroy_ht;
	}

	if (!debugfs_create_file("switch", 0444, dir, NULL, &cnt_fops))
	{
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
