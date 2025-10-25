/*
* energy_proc - per-PID runtime/PMU stats + Intel-RAPL (MSR) energy
*
* Original author:  Didi Hoffmann <didi@ribalba.de>
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
#include <linux/workqueue.h>
#include <linux/math64.h>
#include <linux/stdarg.h>
#include <linux/printk.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <linux/cpumask.h>
#include <linux/cgroup.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kernel_stat.h>
#include <linux/sched/cputime.h>
#include <trace/events/block.h>
#include <trace/events/sched.h>
#include <linux/netdevice.h>
#include <linux/blkdev.h>
#include <linux/mmzone.h>

#define DRV_NAME    "energy_proc"
#define PM_LINE_MAX 256

#ifndef CGROUP_NAME_LEN
#define CGROUP_NAME_LEN 128
#endif

// The kernel does not have floats so we need to build one ourself. We use a fixed point representation
//#define ENERGY_SCALE 1000ULL

/* ───────────────── Module parameters ─────────────────────────────────── */

static unsigned long long sample_ns = 100ULL * NSEC_PER_MSEC;
module_param(sample_ns, ullong, 0644);
MODULE_PARM_DESC(sample_ns, "Sampling period in nanoseconds (default: 100 ms)");

static unsigned long long window_ns = NSEC_PER_SEC;
module_param(window_ns, ullong, 0644);
MODULE_PARM_DESC(window_ns, "The window for calculting the values in nanoseconds (default: 1s)");


static u64 w_cpu_ns           = 5;
static u64 w_mem_bytes        = 0;
static u64 w_instructions     = 5;
static u64 w_wakeups          = 0;
static u64 w_disk_read_bytes  = 0;
static u64 w_disk_write_bytes = 0;
static u64 w_net_rx_packets   = 0;
static u64 w_net_tx_packets   = 0;

#define ENERGY_PARAM(_name)                                  \
    module_param(_name, ullong, 0644);                       \
    MODULE_PARM_DESC(_name, "Weight for " #_name);

ENERGY_PARAM(w_cpu_ns)
ENERGY_PARAM(w_mem_bytes)
ENERGY_PARAM(w_instructions)
ENERGY_PARAM(w_wakeups)
ENERGY_PARAM(w_disk_read_bytes)
ENERGY_PARAM(w_disk_write_bytes)
ENERGY_PARAM(w_net_rx_packets)
ENERGY_PARAM(w_net_tx_packets)

#undef ENERGY_PARAM


/* ───────────────── Globals ────────────────────────────────── */

static bool pmu_supported; // instructions via PMU

// The workqueue for sampling
static struct workqueue_struct *pm_wq;
static struct delayed_work     collect_work;

// The workqueue for windowing
static struct workqueue_struct *win_wq;
static struct delayed_work     win_work;

// Atomic counter for the number of iterations
static atomic64_t iterations;

// Procfs entries
static struct proc_dir_entry *energy_dir;
static struct proc_dir_entry *cgroup_proc_file;
static struct proc_dir_entry *all_proc_file;


/* ───────────────── Per-PID hash-table entry ─────────────────────────── */

struct pid_metrics {
    u32  pid;
    char comm[TASK_COMM_LEN];
    bool is_kernel;
    int  alive;

    u64             cpu_ns;
    u64             instructions;
    u64             wakeups;
    atomic64_t      net_rx_packets;
    atomic64_t      net_tx_packets;
    u64             disk_read_bytes;
    u64             disk_write_bytes;
    u64             mem_bytes;


    u64 window_cpu_ns;
    u64 window_instructions;
    u64 window_wakeups;
    u64 window_net_rx_packets;
    u64 window_net_tx_packets;
    u64 window_disk_read_bytes;
    u64 window_disk_write_bytes;
    u64 window_mem_bytes;
    u64 window_energy_uj;
    u64 window_timestamp_ns;

    /* internals */
    struct rhash_head   node;
    unsigned long       last_seen;
    struct perf_event   *insn_evt;
    struct rcu_head     rcu;
};

static const struct rhashtable_params ht_params = {
    .key_len            = sizeof(u32),
    .key_offset         = offsetof(struct pid_metrics, pid),
    .head_offset        = offsetof(struct pid_metrics, node),
    .automatic_shrinking = true,
    .nelem_hint         = 1024,
};

static struct rhashtable pid_ht;
static struct kmem_cache *pm_cache;

/* ─────────────── System-wide metrics (independent source) ───────────── */

static struct pid_metrics sys_metrics;
static struct perf_event *insn_cpu_evt[NR_CPUS];

static atomic64_t sys_wakeups;
static atomic64_t sys_disk_read_bytes_atomic;
static atomic64_t sys_disk_write_bytes_atomic;

static struct tracepoint *tp_blk_complete;
static struct tracepoint *tp_sched_wakeup;
static struct tracepoint *tp_sched_wakeup_new;
static struct tracepoint *tp_tx;

/* ───────────────── RAPL via MSR (core / psys) ────────────────────────── */

struct rapl_domain {
    u32 msr;           /* MSR_*_ENERGY_STATUS */
    bool supported;
    u64 last_raw;      /* raw counter (wraps at 32 bits) */
    u64 delta_uj;      /* scaled Δ since previous sample (µJ) */
    u64 sum;           /* sum of all deltas */
};

static struct rapl_domain rapl_core  = { .msr = MSR_PP0_ENERGY_STATUS };
static struct rapl_domain rapl_psys  = { .msr = MSR_PLATFORM_ENERGY_STATUS };

static bool rapl_core_supported;
static bool rapl_psys_supported;

/* Reciprocal of energy unit (2-N J) in µJ << 16  ➜  multiply then >>16.   */
static u64 rapl_energy_inv_uj;

/* Detect presence + energy unit once at load time */
static void detect_rapl(void)
{
    u32 lo, hi;
    unsigned int cpu0 = cpumask_first(cpu_online_mask);

    /* ---- energy unit ------------------------------------------------ */
    if (!rdmsr_safe_on_cpu(cpu0, MSR_RAPL_POWER_UNIT, &lo, &hi)) {
        u32 e_shift = (lo >> 8) & 0x1f; /* bits [12:8] */
        rapl_energy_inv_uj =
            div_u64(1000000ULL << 16, 1ULL << e_shift);
    }else{
        rapl_core.supported = false;
        rapl_psys.supported = false;
        pr_warn(DRV_NAME ": RAPL MSR_RAPL_POWER_UNIT not available - energy metrics off\n");
        return;
    }

    /* ---- core domain (PP0) ----------------------------------------- */
    if (!rdmsr_safe_on_cpu(cpu0, rapl_core.msr, &lo, &hi)) {
        rapl_core.supported = true;
        rapl_core.last_raw  = ((u64)hi << 32) | lo;
    }

    /* ---- psys domain (package/platform) ---------------------------- */
    if (!rdmsr_safe_on_cpu(cpu0, rapl_psys.msr, &lo, &hi)) {
        rapl_psys.supported = true;
        rapl_psys.last_raw  = ((u64)hi << 32) | lo;
    }

    rapl_core_supported = rapl_core.supported;
    rapl_psys_supported = rapl_psys.supported;

    if (!rapl_core_supported){
        pr_info(DRV_NAME ": RAPL core MSRs not available - energy metrics off\n");
    }

    if (!rapl_psys_supported){
        pr_info(DRV_NAME ": RAPL psys MSRs not available - energy metrics off\n");
    }

}

static void rapl_compute_delta(struct rapl_domain *d)
{
    if (!d->supported)
        return;

    u32 lo, hi;
    unsigned int cpu0 = cpumask_first(cpu_online_mask);

    if (rdmsr_safe_on_cpu(cpu0, d->msr, &lo, &hi))
        return;                 /* read failed */

    u64 now = ((u64)hi << 32) | lo;
    u64 raw_delta = (now >= d->last_raw)
        ? now - d->last_raw
        : now + (1ULL << 32) - d->last_raw;  /* 32-bit wrap */

    d->last_raw = now;
    d->delta_uj = rapl_energy_inv_uj
        ? (raw_delta * rapl_energy_inv_uj) >> 16
        : raw_delta;   /* fallback: raw count */

    d->sum += d->delta_uj;
}

/* ─────────────────System wide collector functions ─────────────────────────── */


static u64 sys_cpu_busy_ns(void)
{
    u64 ns = 0;
    int cpu;
    for_each_online_cpu(cpu) {
        struct kernel_cpustat *kcs = &kcpustat_cpu(cpu);
        ns += kcs->cpustat[CPUTIME_USER]     +
              kcs->cpustat[CPUTIME_NICE]     +
              kcs->cpustat[CPUTIME_SYSTEM];
            //   kcs->cpustat[CPUTIME_IRQ]      +
            //   kcs->cpustat[CPUTIME_SOFTIRQ]  +
            //   kcs->cpustat[CPUTIME_STEAL];
    }

    return ns;
}

static u64 sys_instructions_read(void)
{
    if (!pmu_supported) return 0;

    u64 tot = 0; int cpu;
    for_each_online_cpu(cpu) {
        if (insn_cpu_evt[cpu]) {
            u64 en = 0, run = 0;
            tot += perf_event_read_value(insn_cpu_evt[cpu], &en, &run);
        }
    }
    return tot;
}

static u64 sys_wakeups_read(void)
{
    return (u64)atomic64_read(&sys_wakeups);
}

static void sys_net_packets_read(u64 *rx, u64 *tx)
{
    struct net_device *dev;
    struct rtnl_link_stats64 tmp, *st;
    *rx = *tx = 0;

    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
        st = dev_get_stats(dev, &tmp);
        if (st) {
            *rx += st->rx_packets;
            *tx += st->tx_packets;
        }
    }
    rcu_read_unlock();
}

static u64 sys_mapped_mem_bytes_read(void)
{
    unsigned long anon  = global_node_page_state(NR_ANON_MAPPED);
    unsigned long filem = global_node_page_state(NR_FILE_MAPPED);
    unsigned long shmem = global_node_page_state(NR_SHMEM);
    return ((u64)anon + (u64)filem + (u64)shmem) << PAGE_SHIFT;
}


static int sys_pmu_init(void)
{
    int cpu;

    if (!pmu_supported)
        return 0;

    struct perf_event_attr attr = {
        .type       = PERF_TYPE_HARDWARE,
        .config     = PERF_COUNT_HW_INSTRUCTIONS,
        .size       = sizeof(attr),
        .disabled   = 1,
        .exclude_hv = 1,
        .inherit    = 0,  /* CPU-wide, not per-task */
    };

    for_each_online_cpu(cpu) {
        insn_cpu_evt[cpu] = perf_event_create_kernel_counter(
            &attr, cpu, NULL, NULL, NULL);
        if (!IS_ERR(insn_cpu_evt[cpu])) {
            perf_event_enable(insn_cpu_evt[cpu]);
        } else {
            insn_cpu_evt[cpu] = NULL;
            pr_warn(DRV_NAME ": CPU%u: system PMU setup failed\n", cpu);
        }
    }
    return 0;
}

static void sys_pmu_exit(void)
{
    int cpu;
    for_each_possible_cpu(cpu) {
        if (insn_cpu_evt[cpu]) {
            perf_event_release_kernel(insn_cpu_evt[cpu]);
            insn_cpu_evt[cpu] = NULL;
        }
    }
}



/* ───────────────── Tracepint ─────────────────────────── */

static struct kretprobe   kr_sock_recvmsg;

/* This needs to be in a h file */
static void pm_tp_tx(void *data, struct sk_buff *skb);
static int  kp_sock_recvmsg_entry(struct kretprobe_instance *, struct pt_regs *);
static int  kp_sock_recvmsg_ret(struct kretprobe_instance *, struct pt_regs *);
static int cnt_show(struct seq_file *m, void *v);


static void tp_block_rq_complete_cb(void *ignore,
    struct request *rq, blk_status_t error, unsigned int nr_bytes)
{
    if (!rq) return;
    if (op_is_write(req_op(rq)))
        atomic64_add(nr_bytes, &sys_disk_write_bytes_atomic);
    else
        atomic64_add(nr_bytes, &sys_disk_read_bytes_atomic);
}

static void find_tp_named(struct tracepoint *tp, void *priv)
{
    const char *name = priv;
    if (!strcmp(tp->name, name)) {
        if (!strcmp(name, "net_dev_queue"))          tp_tx = tp;
        else if (!strcmp(name, "sched_wakeup"))      tp_sched_wakeup = tp;
        else if (!strcmp(name, "sched_wakeup_new"))  tp_sched_wakeup_new = tp;
        else if (!strcmp(name, "block_rq_complete"))  tp_blk_complete = tp;

    }
}

static void tp_sched_wakeup_cb(void *data, struct task_struct *p)
{
    atomic64_inc(&sys_wakeups);
}


static int pm_register_tracepoints(void)
{
    int err;

    /* find needed tracepoints */
    for_each_kernel_tracepoint(find_tp_named, "net_dev_queue");
    for_each_kernel_tracepoint(find_tp_named, "sched_wakeup");
    for_each_kernel_tracepoint(find_tp_named, "sched_wakeup_new");
    for_each_kernel_tracepoint(find_tp_named, "block_rq_complete");

    if (!tp_tx || !tp_sched_wakeup || !tp_sched_wakeup_new || !tp_blk_complete)
        return -ENOENT;

    err = tracepoint_probe_register(tp_tx, pm_tp_tx, NULL);
    if (err)
        return err;

    err = tracepoint_probe_register(tp_blk_complete, tp_block_rq_complete_cb, NULL);
    if (err){
        tracepoint_probe_unregister(tp_tx, pm_tp_tx, NULL);
        return err;
    }

    err = tracepoint_probe_register(tp_sched_wakeup,     tp_sched_wakeup_cb, NULL);
    if (err){
        tracepoint_probe_unregister(tp_tx, pm_tp_tx, NULL);
        tracepoint_probe_unregister(tp_blk_complete, tp_block_rq_complete_cb, NULL);
        return err;
    }

    err = tracepoint_probe_register(tp_sched_wakeup_new, tp_sched_wakeup_cb, NULL);
    if (err){
        tracepoint_probe_unregister(tp_tx, pm_tp_tx, NULL);
        tracepoint_probe_unregister(tp_blk_complete, tp_block_rq_complete_cb, NULL);
        tracepoint_probe_unregister(tp_sched_wakeup, tp_sched_wakeup_cb, NULL);
        return err;
    }

    kr_sock_recvmsg.kp.symbol_name = "sock_recvmsg";
    kr_sock_recvmsg.entry_handler  = kp_sock_recvmsg_entry;
    kr_sock_recvmsg.handler        = kp_sock_recvmsg_ret;
    kr_sock_recvmsg.maxactive      = 64;

    err = register_kretprobe(&kr_sock_recvmsg);
    if (err) {
        tracepoint_probe_unregister(tp_tx, pm_tp_tx, NULL);
        tracepoint_probe_unregister(tp_blk_complete, tp_block_rq_complete_cb, NULL);
        tracepoint_probe_unregister(tp_sched_wakeup, tp_sched_wakeup_cb, NULL);
        tracepoint_probe_unregister(tp_sched_wakeup_new, tp_sched_wakeup_cb, NULL);
        return err;
    }
    return 0;
}


static void pm_unregister_tracepoints(void)
{
    unregister_kretprobe(&kr_sock_recvmsg);

    if (tp_tx)                 tracepoint_probe_unregister(tp_tx, pm_tp_tx, NULL);
    if (tp_blk_complete)       tracepoint_probe_unregister(tp_blk_complete, tp_block_rq_complete_cb, NULL);
    if (tp_sched_wakeup)       tracepoint_probe_unregister(tp_sched_wakeup, tp_sched_wakeup_cb, NULL);
    if (tp_sched_wakeup_new)   tracepoint_probe_unregister(tp_sched_wakeup_new, tp_sched_wakeup_cb, NULL);

    tracepoint_synchronize_unregister();
}


/* TX tracepoint */
static void pm_tp_tx(void *data, struct sk_buff *skb)
{
    u32 tgid = task_tgid_nr(current);

    rcu_read_lock();
    struct pid_metrics *pm =
        rhashtable_lookup_fast(&pid_ht, &tgid, ht_params);
    if (pm && pm->alive)
        atomic64_inc(&pm->net_tx_packets);
    rcu_read_unlock();
}

/* RX kretprobe */
static int kp_sock_recvmsg_entry(struct kretprobe_instance *ri,
                struct pt_regs *regs)
{
    return 0;
}

static int kp_sock_recvmsg_ret(struct kretprobe_instance *ri,
                struct pt_regs *regs)
{
    long ret = regs_return_value(regs);
    if (ret <= 0)
        return 0;

    u32 tgid = task_tgid_nr(current);

    rcu_read_lock();
    struct pid_metrics *pm =
        rhashtable_lookup_fast(&pid_ht, &tgid, ht_params);
    if (pm)
        atomic64_inc(&pm->net_rx_packets);
    rcu_read_unlock();

    return 0;
}

static u64 energy_model(const struct pid_metrics *e)
{

    u64 score = 0;

    score += e->cpu_ns                            * w_cpu_ns;
    score += e->mem_bytes                         * w_mem_bytes;
    score += (pmu_supported ? e->instructions : 0) * w_instructions;
    score += e->wakeups                           * w_wakeups;
    score += e->disk_read_bytes                   * w_disk_read_bytes;
    score += e->disk_write_bytes                  * w_disk_write_bytes;
    score += (u64)atomic64_read(&e->net_rx_packets)    * w_net_rx_packets;
    score += (u64)atomic64_read(&e->net_tx_packets)    * w_net_tx_packets;

    return score;
}


/* ───────────────── Misc helpers ─────────────────────────────────────── */

static bool pid_still_alive(u32 pid)
{
    bool alive;

    rcu_read_lock();
    struct task_struct *p = pid_task(find_vpid(pid), PIDTYPE_PID);
    alive = p && pid_alive(p);
    rcu_read_unlock();

    return alive;
}

// We keep this if we want to revert to fixed point representation
// static void seq_print_fixed(struct seq_file *m, u64 scaled)
// {
//     u64 int_part  = div_u64(scaled, ENERGY_SCALE);
//     u64 frac_part = scaled % ENERGY_SCALE;

//     seq_printf(m, "%llu.%03llu", int_part, frac_part);
//}


static void print_pm(struct seq_file *m, struct pid_metrics *e){
    seq_printf(m, "pid=%u ", e->pid);

    u64 e_score = energy_model(e);
    seq_printf(m, "energy=%llu ", e_score);
    //seq_print_fixed(m, e_score);
    //seq_puts(m, " ");

    seq_printf(m,
    "alive=%d kernel=%d cpu_ns=%llu mem=%llu ",
    e->alive, e->is_kernel,
    e->cpu_ns, e->mem_bytes);


    if (pmu_supported)
        seq_printf(m, "instructions=%llu ", e->instructions);

    seq_printf(m,
        "wakeups=%llu diski=%llu disko=%llu rx=%llu tx=%llu comm=%s\n",
        e->wakeups,
        e->disk_read_bytes,
        e->disk_write_bytes,
        (u64)atomic64_read(&e->net_rx_packets),
        (u64)atomic64_read(&e->net_tx_packets),
        e->comm);
}

static void print_pm_window(struct seq_file *m, struct pid_metrics *e){
    seq_printf(m, "pid=%u ", e->pid);
    seq_printf(m, "energy=%llu ", e->window_energy_uj);
    seq_printf(m,
    "alive=%d kernel=%d cpu_ns=%llu mem=%llu ",
    e->alive, e->is_kernel,
    e->window_cpu_ns, e->window_mem_bytes);


    if (pmu_supported)
        seq_printf(m, "instructions=%llu ", e->window_instructions);

    seq_printf(m,
        "wakeups=%llu diski=%llu disko=%llu rx=%llu tx=%llu window_time=%llu comm=%s\n",
        e->window_wakeups,
        e->window_disk_read_bytes,
        e->window_disk_write_bytes,
        e->window_net_rx_packets,
        e->window_net_tx_packets,
        e->window_timestamp_ns,
        e->comm);
}

/* ───────────────── PMU capability check (instructions) ─────────────── */

static void detect_pmu(void)
{
    struct perf_event_attr attr = {
        .type       = PERF_TYPE_HARDWARE,
        .config     = PERF_COUNT_HW_INSTRUCTIONS,
        .size       = sizeof(attr),
        .disabled   = 1,
        .exclude_hv = 1,
    };
    struct perf_event *evt =
        perf_event_create_kernel_counter(&attr, -1, current, NULL, NULL);

    if (IS_ERR(evt)) {
        pmu_supported = false;
        pr_warn_once(DRV_NAME": PMU not present - instructions metric disabled\n");
        return;
    }
    perf_event_release_kernel(evt);
    pmu_supported = true;
}

/* ───────────────── Sampling worker ──────────────────────────────────── */

static void rapl_sample_once(void)
{
    if (rapl_core_supported){
        rapl_compute_delta(&rapl_core);
    }

    if (rapl_psys_supported){
        rapl_compute_delta(&rapl_psys);
    }
}

static void collect_values(struct work_struct *wk)
{
    atomic64_inc(&iterations);

    struct delayed_work *dw = to_delayed_work(wk);
    struct task_struct *p, *t;

    rapl_sample_once();


    { // This is the system-wide entry
        u64 rx = 0, tx = 0;

        sys_metrics.cpu_ns           = sys_cpu_busy_ns();
        sys_metrics.instructions     = sys_instructions_read();
        sys_metrics.wakeups          = sys_wakeups_read();
        sys_net_packets_read(&rx, &tx);
        atomic64_set(&sys_metrics.net_rx_packets, rx);
        atomic64_set(&sys_metrics.net_tx_packets, tx);
        sys_metrics.disk_read_bytes  = (u64)atomic64_read(&sys_disk_read_bytes_atomic);
        sys_metrics.disk_write_bytes = (u64)atomic64_read(&sys_disk_write_bytes_atomic);
        sys_metrics.mem_bytes        = sys_mapped_mem_bytes_read();
    }

    /* iterate tasks */
    for_each_process_thread(p, t) {

        rcu_read_lock();
        u32 tgid = task_tgid_nr(t);
        struct pid_metrics *pm;

        pm = rhashtable_lookup_fast(&pid_ht, &tgid, ht_params);

        if (!pm) {
            pm = kmem_cache_zalloc(pm_cache, GFP_KERNEL);
            if (!pm)
                continue;

            pm->pid = tgid;
            get_task_comm(pm->comm, p);

            if (rhashtable_insert_fast(&pid_ht, &pm->node, ht_params)) {
                kmem_cache_free(pm_cache, pm);
                continue;
            }

            if (pmu_supported) {
                struct perf_event_attr attr = {
                    .type       = PERF_TYPE_HARDWARE,
                    .config     = PERF_COUNT_HW_INSTRUCTIONS,
                    .size       = sizeof(attr),
                    .disabled   = 1,
                    .exclude_hv = 1,
                    .inherit    = 1,
                };
                pm->insn_evt =
                    perf_event_create_kernel_counter(
                            &attr, -1, p,
                            NULL, NULL);
                if (!IS_ERR(pm->insn_evt))
                    perf_event_enable(pm->insn_evt);
                else
                    pm->insn_evt = NULL;
            }
            pm->is_kernel = (p->flags & PF_KTHREAD) || !p->mm;
        }


        /* collect metrics */
        pm->alive            = 1;
        pm->last_seen        = jiffies;
        pm->cpu_ns           += t->se.sum_exec_runtime;

        #ifdef CONFIG_SCHEDSTATS
            pm->wakeups          += t->stats.nr_wakeups;
        #else
            pm->wakeups          = 0;
        #endif

        #ifdef CONFIG_TASK_IO_ACCOUNTING
            pm->disk_read_bytes  += t->ioac.read_bytes;
            pm->disk_write_bytes += t->ioac.write_bytes;
        #else
            pm->disk_read_bytes  = 0;
            pm->disk_write_bytes = 0;
        #endif

        rcu_read_unlock();
    }


    for_each_process(p) {
        u32 tgid = task_tgid_nr(p);
        struct pid_metrics *pm;
        rcu_read_lock();
        pm = rhashtable_lookup_fast(&pid_ht, &tgid, ht_params);
        rcu_read_unlock();
        if (!pm) continue;

        struct mm_struct *mm = get_task_mm(p);
        if (mm) { pm->mem_bytes = (u64)get_mm_rss(mm) << PAGE_SHIFT; mmput(mm); }
        else     pm->mem_bytes = 0;
    }

    /* lazy eviction */
    struct rhashtable_iter iter;
    struct pid_metrics *it;


    /* Instructions: read once from the process’ perf event */
    rhashtable_walk_enter(&pid_ht, &iter);
    rhashtable_walk_start(&iter);
    while ((it = rhashtable_walk_next(&iter))) {
        if (IS_ERR(it)) {
            if (PTR_ERR(it) == -EAGAIN)
                continue;
            break;
        }

        if (it->insn_evt && pmu_supported) {
            u64 en=0, run=0;
            it->instructions = perf_event_read_value(it->insn_evt, &en, &run);
        }
    }
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);


    rhashtable_walk_enter(&pid_ht, &iter);
    rhashtable_walk_start(&iter);
    while ((it = rhashtable_walk_next(&iter))) {
        if (IS_ERR(it)) {
            if (PTR_ERR(it) == -EAGAIN)
                continue;
            break;
        }
        if (it && !pid_still_alive(it->pid)){
            it->alive = 0;
        }
    }
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    queue_delayed_work(pm_wq, dw, nsecs_to_jiffies(sample_ns));
}

static void calculate_window(struct work_struct *wk)
{
    struct delayed_work *dw = to_delayed_work(wk);

    struct rhashtable_iter iter;
    struct pid_metrics *it;

    rhashtable_walk_enter(&pid_ht, &iter);
    rhashtable_walk_start(&iter);
    while ((it = rhashtable_walk_next(&iter)) && !IS_ERR(it)){
        if (it->alive == 1){
            it->window_cpu_ns          = it->cpu_ns;
            it->window_instructions    = it->instructions;
            it->window_wakeups         = it->wakeups;
            it->window_mem_bytes       = it->mem_bytes;
            it->window_disk_read_bytes = it->disk_read_bytes;
            it->window_disk_write_bytes= it->disk_write_bytes;
            it->window_net_rx_packets  = (u64)atomic64_read(&it->net_rx_packets);
            it->window_net_tx_packets  = (u64)atomic64_read(&it->net_tx_packets);

            it->window_energy_uj       = energy_model(it);
            it->window_timestamp_ns    = ktime_get_ns();
        }
    }
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);


    sys_metrics.window_cpu_ns           = sys_metrics.cpu_ns;
    sys_metrics.window_instructions     = sys_metrics.instructions;
    sys_metrics.window_wakeups          = sys_metrics.wakeups;
    sys_metrics.window_mem_bytes        = sys_metrics.mem_bytes;
    sys_metrics.window_disk_read_bytes  = sys_metrics.disk_read_bytes;
    sys_metrics.window_disk_write_bytes = sys_metrics.disk_write_bytes;
    sys_metrics.window_net_rx_packets   = (u64)atomic64_read(&sys_metrics.net_rx_packets);
    sys_metrics.window_net_tx_packets   = (u64)atomic64_read(&sys_metrics.net_tx_packets);
    sys_metrics.window_energy_uj        = energy_model(&sys_metrics);
    sys_metrics.window_timestamp_ns     = ktime_get_ns();

    queue_delayed_work(win_wq, dw, nsecs_to_jiffies(window_ns));
}

/* ───────────────── /energy/switch debugfs file ──────────────────────── */

static int sys_only_show(struct seq_file *m, void *v)
{
    seq_printf(m, "timestamp=%llu\n", ktime_get_ns());
    seq_printf(m, "iterations=%llu\n", (u64)atomic64_read(&iterations));
    seq_printf(m, "sample_ns=%llu\n", sample_ns);
    seq_printf(m, "window_ns=%llu\n", window_ns);

    if (rapl_core_supported)
        seq_printf(m, "rapl_core_sum_uj=%llu\n", rapl_core.sum);
    if (rapl_psys_supported)
        seq_printf(m, "rapl_psys_sum_uj=%llu\n", rapl_psys.sum);

    print_pm(m, &sys_metrics);

    return 0;
}

static int sys_only_open(struct inode *inode, struct file *file)
{
    if (!capable(CAP_SYS_ADMIN)){
        pr_info(DRV_NAME ": sys-only debug endpoint requires CAP_SYS_ADMIN\n");
        return -EACCES;
    }
    return single_open(file, sys_only_show, NULL);
}

static const struct file_operations sys_only_fops = {
    .owner   = THIS_MODULE,
    .open    = sys_only_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

static int cnt_show(struct seq_file *m, void *v)
{
    struct rhashtable_iter iter;
    struct pid_metrics *e;

    rhashtable_walk_enter(&pid_ht, &iter);
    rhashtable_walk_start(&iter);

    seq_printf(m, "timestamp=%llu\n", ktime_get_ns()); // This always needs to be first for parsing
    seq_printf(m, "iterations=%llu\n", (u64)atomic64_read(&iterations));
    seq_printf(m, "sample_ns=%llu\n", sample_ns);
    seq_printf(m, "window_ns=%llu\n", window_ns);

    if (rapl_core_supported){
        //seq_printf(m, "rapl_core_uj=%llu\n", rapl_core.delta_uj);
        seq_printf(m, "rapl_core_sum_uj=%llu\n", rapl_core.sum);
    }

    if (rapl_psys_supported){
        //seq_printf(m, "rapl_psys_uj=%llu\n", rapl_psys.delta_uj);
        seq_printf(m, "rapl_psys_sum_uj=%llu\n", rapl_psys.sum);
    }

    print_pm(m, &sys_metrics);

    while ((e = rhashtable_walk_next(&iter))) {
        if (IS_ERR(e)) {
            if (PTR_ERR(e) == -EAGAIN)
                continue;
            break;
        }
        if (e){
            print_pm(m, e);
        }
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);
    return 0;
}

static int cnt_open(struct inode *inode, struct file *file)
{
    if (!capable(CAP_SYS_ADMIN)){
        pr_info(DRV_NAME ": it is not possible to access the all list in a container!\n");
        return -EACCES;
    }

    return single_open(file, cnt_show, NULL);
}

static const struct file_operations cnt_fops = {
    .owner   = THIS_MODULE,
    .open    = cnt_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

/* ───────────────── proc cgroup ───────────────────────────────── */

static void cg_get_name(struct cgroup *cg, char *buf, size_t len)
{
    struct kernfs_node *kn = READ_ONCE(cg->kn);
    if (kn && kn->name)
        strscpy(buf, kn->name, len);
    else
        strscpy(buf, "?", len);
}


static int cgroup_energy_show(struct seq_file *m, void *v){
    struct cgroup *cgrp = task_dfl_cgroup(current);

    char cgname[CGROUP_NAME_LEN];

    cg_get_name(cgrp, cgname, sizeof(cgname));
    //seq_printf(m, "cgroup: %s\n", cgname);

    struct task_struct *p, *t;

    rcu_read_lock();
    for_each_process_thread(p, t) {
        if (task_dfl_cgroup(t) == cgrp){
            struct pid_metrics *pm = rhashtable_lookup_fast(&pid_ht, &t->pid, ht_params);
            if (pm && READ_ONCE(pm->alive)){
                print_pm_window(m, pm);
            }
        }
    }
    rcu_read_unlock();

    return 0;
}

static int cgroup_energy_open(struct inode *inode, struct file *file){
    return single_open(file, cgroup_energy_show, NULL);
}


static const struct proc_ops cgroup_energy_proc_ops = {
    .proc_open    = cgroup_energy_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};


/* ───────────────── proc all ───────────────────────────────── */


static const struct proc_ops all_energy_proc_ops = {
    .proc_open    = cnt_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ───────────────── Module init / exit ───────────────────────────────── */

static struct dentry *dir;

static int __init pidmetrics_init(void)
{
    int ret;

    pr_info(DRV_NAME ": loading …\n");

    detect_pmu();
    detect_rapl();

    if ((ret = sys_pmu_init()))
        pr_warn(DRV_NAME ": system PMU init returned %d\n", ret);

    /* initialize globals */
    memset(&sys_metrics, 0, sizeof(sys_metrics));
    sys_metrics.pid = 0;
    strscpy(sys_metrics.comm, "*system*", sizeof(sys_metrics.comm));
    sys_metrics.is_kernel = 1;
    sys_metrics.alive = 1;
    atomic64_set(&sys_wakeups, 0);
    atomic64_set(&iterations, 0);

    pm_cache = KMEM_CACHE(pid_metrics, SLAB_HWCACHE_ALIGN | SLAB_PANIC);

    ret = rhashtable_init(&pid_ht, &ht_params);
    if (ret)
        goto err_cache;

    ret = pm_register_tracepoints();
    if (ret)
        goto err_ht;

    // Debugfs setup that just dumps everything. This is only accessible by root!
    dir = debugfs_create_dir("energy", NULL);
    if (!dir) {
        ret = -ENOMEM;
        goto err_trace;
    }

    if (!debugfs_create_file("all", 0444, dir, NULL, &cnt_fops)) {
        ret = -ENOMEM;
        goto err_debugfs;
    }

    pr_info(DRV_NAME ": created /sys/kernel/debug/energy/all\n");

    if (!debugfs_create_file("sys", 0444, dir, NULL, &sys_only_fops)) {
        ret = -ENOMEM;
        goto err_debugfs;
    }

    pr_info(DRV_NAME ": created /sys/kernel/debug/energy/sys\n");

    // Procfs setup
    energy_dir = proc_mkdir("energy", NULL);
    if (!energy_dir) {
        ret = -ENOMEM;
        goto err_remove_proc;
    }

    cgroup_proc_file = proc_create("cgroup", 0444, energy_dir, &cgroup_energy_proc_ops);
    if (!cgroup_proc_file) {
        ret = -ENOMEM;
        goto err_remove_proc;
    }

    pr_info(DRV_NAME ": created /proc/energy/cgroup\n");

    all_proc_file = proc_create("all", 0400, energy_dir, &all_energy_proc_ops);
    if (!all_proc_file) {
        ret = -ENOMEM;
        goto err_remove_proc;
    }

    pr_info(DRV_NAME ": created /proc/energy/all\n");

    // The collection workqueue
    INIT_DELAYED_WORK(&collect_work, collect_values);
    pm_wq = alloc_workqueue("energy_proc_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    if (!pm_wq) {
        ret = -ENOMEM;
        goto err_remove_proc;
    }
    queue_delayed_work(pm_wq, &collect_work, 0);


    INIT_DELAYED_WORK(&win_work, calculate_window);
    win_wq = alloc_workqueue("energy_proc_window_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    if (!win_wq) {
        ret = -ENOMEM;
        goto err_wq;
    }
    queue_delayed_work(win_wq, &win_work, nsecs_to_jiffies(window_ns));

    pr_info(DRV_NAME ": sampling every %llu ms "
        "(PMU %s / RAPL core=%d psys=%d)\n",
        sample_ns / NSEC_PER_MSEC,
        pmu_supported ? "on" : "off",
        rapl_core_supported,
        rapl_psys_supported);

    return 0;

err_wq:
    if (pm_wq)
        destroy_workqueue(pm_wq);
err_remove_proc:
    if (cgroup_proc_file)
        proc_remove(cgroup_proc_file);
    if (all_proc_file)
        proc_remove(all_proc_file);
    if (energy_dir)
        proc_remove(energy_dir);
err_debugfs:
    debugfs_remove_recursive(dir);
err_trace:
    pm_unregister_tracepoints();
err_ht:
    rhashtable_destroy(&pid_ht);
err_cache:
    kmem_cache_destroy(pm_cache);
    return ret;
}

static void free_pm(void *ptr, void *arg)
{
    struct pid_metrics *pm = ptr;
    if (pm->insn_evt)
        perf_event_release_kernel(pm->insn_evt);
    kmem_cache_free(pm_cache, pm);
}

static void __exit pidmetrics_exit(void)
{
    cancel_delayed_work_sync(&collect_work);
    cancel_delayed_work_sync(&win_work);

    if (pm_wq)
        destroy_workqueue(pm_wq);

    if (win_wq)
        destroy_workqueue(win_wq);

    pm_unregister_tracepoints();

    sys_pmu_exit();

    debugfs_remove_recursive(dir);

    proc_remove(cgroup_proc_file);
    proc_remove(all_proc_file);
    proc_remove(energy_dir);

    rhashtable_free_and_destroy(&pid_ht, free_pm, NULL);
    pr_info(DRV_NAME ": unloaded. Bye!\n");
}

module_init(pidmetrics_init);
module_exit(pidmetrics_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Didi Hoffmann <didi@ribalba.de>");
MODULE_DESCRIPTION("Per-PID energy metrics right from the kernel");
MODULE_VERSION("0.1");
