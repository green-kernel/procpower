#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/atomic.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/sched.h>
#include <linux/rhashtable.h>
#include <linux/spinlock.h>
#include <trace/events/sched.h>
#include <linux/timer.h>
#include <linux/sched/signal.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>

#define GC_INTERVAL_SEC (1)
#define MAX_DEAD_PIDS_PER_CYCLE 256

static struct delayed_work gc_work;
static struct dentry *dir;
static struct tracepoint *tp_sched_switch;

struct proc_dir_entry *energy_dir, *cgroup_file;

struct pid_metrics {
	u32                     pid;
    bool                    alive;
	u64                     cpu_ns;
	u64                     wakeups;
	u64                     net_rx_packets;
	u64                     net_tx_packets;
	u64                     disk_read_bytes;
	u64                     disk_write_bytes;
	u64                     mem_bytes;

	u64                     last_start_ns;      /* 0 ⇒ not running    */
	u64					 	last_run;
	struct rhash_head       node;
	char                    comm[TASK_COMM_LEN];
	spinlock_t              lock;
    struct rcu_head         rcu;
    struct list_head        gc_list;
};

static const struct rhashtable_params ht_params = {
	.key_len        = sizeof(u32),
	.key_offset     = offsetof(struct pid_metrics, pid),
	.head_offset    = offsetof(struct pid_metrics, node),
	.automatic_shrinking = true,
	.nelem_hint	= 1024,
};

static struct rhashtable pid_ht;
static DEFINE_SPINLOCK(pid_ht_lock);


/* ─────────────────────────── helper: PID → metrics ─────────────────────── */

static struct pid_metrics *lookup_or_create_pid(u32 pid, const char *comm)
{
	struct pid_metrics *m, *new;
    rcu_read_lock();
	m = rhashtable_lookup_fast(&pid_ht, &pid, ht_params);
    rcu_read_unlock();

	if (m)
		return m;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	new->pid = pid;
	strscpy(new->comm, comm ? comm : "<unknown>", TASK_COMM_LEN);

	spin_lock(&pid_ht_lock);
	m = rhashtable_lookup_fast(&pid_ht, &pid, ht_params);
	if (m) {
		kfree(new);
	} else {
		if (rhashtable_insert_fast(&pid_ht, &new->node, ht_params)) {
			kfree(new);
			new = NULL;
		}
		m = new;
	}
	spin_unlock(&pid_ht_lock);

	return m;
}

static void clean_pids(struct work_struct *work)
{
    pr_info("Garbage collection\n");

    struct rhashtable_iter iter;
    struct pid_metrics *entry;
    struct pid *pid_struct;
    u32 *dead_pids;
    int dead_count = 0;

	dead_pids = kcalloc(MAX_DEAD_PIDS_PER_CYCLE, sizeof(u32), GFP_KERNEL);
    if (!dead_pids) {
        pr_err("Failed to allocate memory for dead_pids\n");
        return;
    }

    rhashtable_walk_enter(&pid_ht, &iter);
    rhashtable_walk_start(&iter);

    while ((entry = rhashtable_walk_next(&iter))) {
        if (IS_ERR(entry)) {
            if (PTR_ERR(entry) == -EAGAIN)
                continue;
            break;
        }

        rcu_read_lock();
        task = pid_task(find_vpid(entry->pid), PIDTYPE_PID);
        rcu_read_unlock();
        if (!task) {
    			dead_pids[dead_count++] = entry->pid;
        }
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    if (dead_count > 0)
        pr_info("Calling GC on %d pids\n", dead_count);


    for (int i = 0; i < dead_count; i++) {
        struct pid_metrics *metric_to_remove;

        spin_lock(&pid_ht_lock);

        rcu_read_lock();
        metric_to_remove = rhashtable_lookup_fast(&pid_ht, &dead_pids[i], ht_params);
        if (metric_to_remove) {
            task = pid_task(find_vpid(metric_to_remove->pid), PIDTYPE_PID);
            if (!task) {
                metric_to_remove->alive = false;
                //rhashtable_remove_fast(&pid_ht, &metric_to_remove->node, ht_params);
                //kfree_rcu(metric_to_remove, rcu);
            }
        }
        rcu_read_unlock();
        spin_unlock(&pid_ht_lock);
    }

    kfree(dead_pids);

	schedule_delayed_work(&gc_work, GC_INTERVAL_SEC * HZ);
}

static void count_sched_switch(void *data, bool preempt,
                               struct task_struct *prev,
                               struct task_struct *next){
	u64 ts = ktime_get_ns();

	if (prev->pid) {
        struct pid_metrics *m = lookup_or_create_pid(prev->pid, prev->comm);
        if (m && m->last_start_ns) {
			spin_lock(&m->lock);
			m->cpu_ns += ts - m->last_start_ns;
            m->last_start_ns = 0;
			m->last_run = ts; // We need this for garbage collection
			spin_unlock(&m->lock);
        }
    }

    if (next->pid) {
        struct pid_metrics *m = lookup_or_create_pid(next->pid, next->comm);
        if (m) {
			spin_lock(&m->lock);
            m->last_start_ns = ts;
            m->wakeups++;
            m->alive = true;
            // Check if it's a userland process with a memory map
            if (!(next->flags & PF_KTHREAD) && next->mm) {
                m->mem_bytes = (u64)next->mm->total_vm << PAGE_SHIFT;
            }
			spin_unlock(&m->lock);
        }
    }
}


static void find_sched_switch_tracepoint(struct tracepoint *tp, void *priv)
{
    if (strcmp(tp->name, "sched_switch") == 0)
        *(struct tracepoint **)priv = tp;

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
            seq_printf(m, "pid=%u alive=%d cpu_ns=%llu mem_byte=%llu comm=%s\n",
                            entry->pid,
                            entry->alive ? 1 : 0,
                            entry->cpu_ns,
                            entry->mem_bytes,
                            entry->comm);
	}
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);


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

static int __init swcnt_init(void)
{
	int ret;
	ret = rhashtable_init(&pid_ht, &ht_params);
	if (ret)
		return ret;

	for_each_kernel_tracepoint(find_sched_switch_tracepoint, &tp_sched_switch);
	if (!tp_sched_switch) {
		pr_err("sched_switch_counter: tracepoint sched_switch not found\n");
		ret = -EINVAL;
		goto err_ht;
	}

	ret = tracepoint_probe_register(tp_sched_switch, count_sched_switch, NULL);
	if (ret) {
		pr_err("sched_switch_counter: failed to register probe: %d\n", ret);
		goto err_ht;
	}

	dir = debugfs_create_dir("energy", NULL);
	if (!dir) {
		pr_err("sched_switch_counter: failed to create debugfs dir\n");
		ret = -ENOMEM;
		goto err_tp_unregister;
	}

	if (!debugfs_create_file("switch", 0444, dir, NULL, &cnt_fops)) {
		pr_err("sched_switch_counter: failed to create debugfs file\n");
		ret = -ENOMEM;
		goto err_debugfs;
	}

	INIT_DELAYED_WORK(&gc_work, clean_pids);
	schedule_delayed_work(&gc_work, GC_INTERVAL_SEC * HZ);

	pr_info("sched_switch_counter: loaded\n");
	return 0;

err_debugfs:
	debugfs_remove_recursive(dir);
err_tp_unregister:
	tracepoint_probe_unregister(tp_sched_switch, count_sched_switch, NULL);
err_ht:
	rhashtable_destroy(&pid_ht);
	return ret;
}

// static void my_elem_free(void *ptr, void *arg)
// {
//         struct my_state *st = arg;
//         struct my_object *obj = ptr;

//         kfree_rcu(obj, rcu);
// }

static void __exit swcnt_exit(void)
{
    struct rhashtable_iter iter;
    struct pid_metrics *entry;

    debugfs_remove_recursive(dir);

    // Stop all new entries and updates from the tracepoint
    tracepoint_probe_unregister(tp_sched_switch, count_sched_switch, NULL);

    // Stop the garbage collector and wait for it to finish
    cancel_delayed_work_sync(&gc_work);

    // Wait for any in-flight tracepoint callbacks to finish.
    tracepoint_synchronize_unregister();

    // Now it's safe to destroy the table and free all objects, as no
    // part of the kernel is still using them.
    // rhashtable_walk_enter(&pid_ht, &iter);
    // rhashtable_walk_start(&iter);
    //  while ((entry = rhashtable_walk_next(&iter))) {
    //     if (!IS_ERR(entry))
    //         kfree(entry);
    // }
    // rhashtable_walk_stop(&iter);
    // rhashtable_walk_exit(&iter);

	// rhashtable_free_and_destroy(&pid_ht, my_elem_free, NULL);
	// rcu_barrier();

    pr_info("sched_switch_counter: unloaded\n");
}

module_init(swcnt_init);
module_exit(swcnt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Didi Hoffmann <didi@ribalba.de>");
MODULE_DESCRIPTION("Tracs all the metrics we need for energy proc and exposes them in /sys/kernel/debug");
