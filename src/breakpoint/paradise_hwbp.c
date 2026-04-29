/*
 * paradise_hwbp.c --- ARM64 硬件断点子系统实现
 *
 * 关键约束:
 *   - hwbp_overflow_handler() 跑在 IRQ/NMI 上下文:
 *       不能 sleep, 不能取 mutex, 不能 copy_to_user.
 *       只能用 spinlock_irqsave + atomic + memcpy.
 *   - register_wide_hw_breakpoint() / unregister_wide_hw_breakpoint() 可以 sleep,
 *     必须在进程上下文 (IOCTL 处理) 里调, 不能在 handler 里调.
 *   - ARM64 上 struct pt_regs 的前 35 个 u64 跟 struct user_pt_regs 完全一致
 *     (regs[31] + sp + pc + pstate), 可以直接 memcpy(sizeof(user_pt_regs)).
 */
#include "paradise_hwbp.h"
#include "paradise_common.h"

#include <linux/atomic.h>
#include <linux/hw_breakpoint.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/err.h>

/* ============================================================================
 * 数据结构
 * ============================================================================
 *
 * 设计变更 (2026-04-29):
 *   原版用 register_wide_hw_breakpoint() 在每个 CPU 上挂同一条 BP, 命中时再
 *   在 handler 里按 current->tgid 过滤. 这种做法在"热点指令" (如游戏每秒
 *   被执行几百万次的 STR X10) 下会让所有 CPU 上的所有进程都触发 ARM64 BP
 *   异常, handler 即使立刻 return 也已付出 trap → IRQ 切换的几千周期, 8 核
 *   被异常吞掉, 目标进程直接 hung 60s+.
 *
 *   现版本改成 register_user_hw_breakpoint() 给目标进程**每个线程**单独挂
 *   一条 BP, 异常只会发生在目标进程的 task 上, 跟原 perf_event_open 后端
 *   的 per-thread 模式完全等价, CPU 不会被其它进程的 unrelated 命中拖死.
 *
 *   缺点: 在 ADD 时刻已存在的 thread 才会被覆盖. 之后新创建的 thread 不会
 *   自动挂上 BP. 对游戏来说这通常无所谓 — 写坐标的那个线程在游戏初始化
 *   阶段就 spawn 了, 我们 ADD 时已存在.
 */

struct hwbp_thread_bp {
    struct list_head node;
    pid_t            tid;                   /* 注册时的 task->pid */
    struct perf_event *bp;                  /* register_user_hw_breakpoint 返回 */
};

struct hwbp_entry {
    struct list_head node;
    pid_t target_pid;                       /* tgid, hit handler 仍按它过滤兜底 */
    uintptr_t addr;
    int type;                               /* HW_BP_TYPE_* */
    int len;
    struct list_head thread_bps;            /* hwbp_thread_bp 链, 一个 thread 一条 */
    int thread_count;                       /* 注册成功的 thread 个数 */
};

static LIST_HEAD(g_hwbp_list);
static DEFINE_MUTEX(g_hwbp_mutex);          /* 保护 g_hwbp_list (add/remove) */

/* ---- hits ring buffer (handler push, ioctl pop) ----
 *
 * 容量 1024 条, 单条 304 字节 → 内核常驻 ~304 KiB. 60fps 下游戏单帧 5-10
 * 命中, 1024 条容量足够 ~10 秒缓冲, 用户态每帧 ioctl 拉一次完全够用.
 */
#define HWBP_RING_SIZE 1024

static struct paradise_hw_breakpoint_hit_info g_hits_ring[HWBP_RING_SIZE];
static u32 g_hits_head;                     /* 下次写入位置 */
static u32 g_hits_tail;                     /* 下次读取位置 */
static u32 g_hits_count;                    /* 当前条数 (受 g_hits_lock 保护) */
static u64 g_hits_dropped_total;            /* ring 满时丢弃的累计条数 (诊断用) */
static DEFINE_SPINLOCK(g_hits_lock);

/* ============================================================================
 * Hit handler (NMI/IRQ 上下文)
 * ========================================================================== */

static void hwbp_overflow_handler(struct perf_event *bp,
                                  struct perf_sample_data *data,
                                  struct pt_regs *regs)
{
    struct hwbp_entry *e;
    struct paradise_hw_breakpoint_hit_info *slot;
    unsigned long flags;
    pid_t cur_tgid;

    if (!bp || !regs) return;

    /* register_user_hw_breakpoint 把 context 设到 perf_event 的
     * overflow_handler_context 上. 我们在 add 路径传的就是 hwbp_entry*. */
    e = (struct hwbp_entry *)bp->overflow_handler_context;
    if (!e) return;

    /* per-thread 模式下 BP 已经只可能在目标进程的某个 thread 上触发, 不再需要
     * tgid 过滤兜底; 但保留一行硬性 sanity check, 防止 (理论上不会发生的)
     * task migrate 异常情况污染 ring. */
    cur_tgid = current ? current->tgid : 0;
    if (cur_tgid != e->target_pid) return;

    /* 入队. handler 上下文不能 sleep, 用 spin_lock_irqsave (跟其他 handler 在
     * 不同 CPU 互斥). lock 内只做定长 memcpy + 4 个标量更新, 短小. */
    spin_lock_irqsave(&g_hits_lock, flags);

    if (g_hits_count >= HWBP_RING_SIZE) {
        /* 满了: 丢最老一条 (前进 tail), 保留最新. 这种"覆盖式"行为对实时
         * 监控更友好, 下游不会因为延迟拉取就拿到一堆几秒前的旧坐标. */
        g_hits_tail = (g_hits_tail + 1) % HWBP_RING_SIZE;
        g_hits_count--;
        g_hits_dropped_total++;
    }

    slot = &g_hits_ring[g_hits_head];
    slot->pid       = cur_tgid;
    slot->timestamp = ktime_get_ns();
    slot->addr      = e->addr;
    /* ARM64: pt_regs 的前 35 个 u64 跟 user_pt_regs 完全一致, 直接 memcpy. */
    memcpy(&slot->regs, regs, sizeof(struct user_pt_regs));

    g_hits_head = (g_hits_head + 1) % HWBP_RING_SIZE;
    g_hits_count++;

    spin_unlock_irqrestore(&g_hits_lock, flags);
}

/* ============================================================================
 * ADD / REMOVE
 * ========================================================================== */

static int translate_bp_type(int user_type, int *kernel_bp_type)
{
    switch (user_type) {
    case HW_BP_TYPE_EXECUTE: *kernel_bp_type = HW_BREAKPOINT_X;  return 0;
    case HW_BP_TYPE_WRITE:   *kernel_bp_type = HW_BREAKPOINT_W;  return 0;
    case HW_BP_TYPE_RW:      *kernel_bp_type = HW_BREAKPOINT_RW; return 0;
    default: return -EINVAL;
    }
}

/* per-thread 注册时一次最多收集多少 thread (sgame 通常 ~150 个 thread, 256 够用). */
#define HWBP_MAX_THREADS_PER_ADD 1024

static int hwbp_add(pid_t target_pid, uintptr_t addr, int type, int len)
{
    struct perf_event_attr attr;
    struct hwbp_entry *e;
    struct pid *pidp;
    struct task_struct *leader, *t;
    struct task_struct **tasks = NULL;
    int n_tasks = 0;
    int kernel_bp_type;
    int ret;
    int i;
    int reg_ok = 0, reg_fail = 0;

    if (target_pid <= 0) return -EINVAL;
    if (addr == 0)       return -EINVAL;

    if (len != 1 && len != 2 && len != 4 && len != 8) return -EINVAL;
    ret = translate_bp_type(type, &kernel_bp_type);
    if (ret) return ret;

    /* 重复 ADD 同一 (pid, addr) 直接返回成功 (幂等). */
    mutex_lock(&g_hwbp_mutex);
    list_for_each_entry(e, &g_hwbp_list, node) {
        if (e->target_pid == target_pid && e->addr == addr) {
            mutex_unlock(&g_hwbp_mutex);
            paradise_info("hwbp_add: dup (pid=%d addr=0x%lx) -> ok\n",
                          target_pid, (unsigned long)addr);
            return 0;
        }
    }
    mutex_unlock(&g_hwbp_mutex);

    /* 1) 拿到目标进程的 group leader. */
    pidp = find_get_pid(target_pid);
    if (!pidp) return -ESRCH;
    leader = get_pid_task(pidp, PIDTYPE_TGID);
    put_pid(pidp);
    if (!leader) return -ESRCH;

    /* 2) 在 RCU 保护下遍历 thread, 仅 get_task_struct 取引用; register 留到锁外做
     *    (perf_event_create_kernel_counter 内部会 mutex_lock + 可能 sleep, 不能在 RCU 内调). */
    tasks = kzalloc(sizeof(*tasks) * HWBP_MAX_THREADS_PER_ADD, GFP_KERNEL);
    if (!tasks) {
        put_task_struct(leader);
        return -ENOMEM;
    }

    rcu_read_lock();
    for_each_thread(leader, t) {
        if (n_tasks >= HWBP_MAX_THREADS_PER_ADD) break;
        get_task_struct(t);
        tasks[n_tasks++] = t;
    }
    rcu_read_unlock();
    put_task_struct(leader);

    if (n_tasks == 0) {
        kfree(tasks);
        return -ESRCH;
    }

    /* 3) 分配 entry, 准备 attr. */
    e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e) {
        for (i = 0; i < n_tasks; i++) put_task_struct(tasks[i]);
        kfree(tasks);
        return -ENOMEM;
    }
    e->target_pid = target_pid;
    e->addr = addr;
    e->type = type;
    e->len = len;
    INIT_LIST_HEAD(&e->thread_bps);

    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len  = len;
    attr.bp_type = kernel_bp_type;
    attr.disabled = 0;

    /* 4) per-thread 注册. 部分 thread 注册失败不致命 (kernel/exiting thread 等会
     *    被 perf_event 拒掉, 跳过即可). */
    for (i = 0; i < n_tasks; i++) {
        struct perf_event *bp;
        struct hwbp_thread_bp *tb;

        bp = register_user_hw_breakpoint(&attr, hwbp_overflow_handler, e, tasks[i]);
        if (IS_ERR_OR_NULL(bp)) {
            reg_fail++;
            put_task_struct(tasks[i]);
            continue;
        }
        tb = kzalloc(sizeof(*tb), GFP_KERNEL);
        if (!tb) {
            unregister_hw_breakpoint(bp);
            reg_fail++;
            put_task_struct(tasks[i]);
            continue;
        }
        tb->bp  = bp;
        tb->tid = tasks[i]->pid;
        list_add(&tb->node, &e->thread_bps);
        reg_ok++;
        put_task_struct(tasks[i]);
    }
    kfree(tasks);

    if (reg_ok == 0) {
        paradise_err("hwbp_add: per-thread register all failed (pid=%d addr=0x%lx fail=%d)\n",
                     target_pid, (unsigned long)addr, reg_fail);
        kfree(e);
        return -EFAULT;
    }

    e->thread_count = reg_ok;

    mutex_lock(&g_hwbp_mutex);
    list_add(&e->node, &g_hwbp_list);
    mutex_unlock(&g_hwbp_mutex);

    paradise_info("hwbp_add: pid=%d addr=0x%lx type=%d len=%d threads=%d (skipped=%d)\n",
                  target_pid, (unsigned long)addr, type, len, reg_ok, reg_fail);
    return 0;
}

static int hwbp_remove(pid_t target_pid, uintptr_t addr)
{
    struct hwbp_entry *e, *tmp, *found = NULL;
    struct hwbp_thread_bp *tb, *tb_tmp;

    mutex_lock(&g_hwbp_mutex);
    list_for_each_entry_safe(e, tmp, &g_hwbp_list, node) {
        if (e->target_pid == target_pid && e->addr == addr) {
            list_del(&e->node);
            found = e;
            break;
        }
    }
    mutex_unlock(&g_hwbp_mutex);

    if (!found) {
        paradise_warn("hwbp_remove: not found (pid=%d addr=0x%lx)\n",
                      target_pid, (unsigned long)addr);
        return -ENOENT;
    }

    /* unregister_hw_breakpoint 可能 sleep, 必须在锁外调. */
    list_for_each_entry_safe(tb, tb_tmp, &found->thread_bps, node) {
        list_del(&tb->node);
        if (tb->bp) unregister_hw_breakpoint(tb->bp);
        kfree(tb);
    }
    kfree(found);

    paradise_info("hwbp_remove: pid=%d addr=0x%lx ok\n",
                  target_pid, (unsigned long)addr);
    return 0;
}

/* ============================================================================
 * IOCTL handlers (进程上下文, 可以 copy_*_user / mutex)
 * ========================================================================== */

int do_hw_breakpoint_ctl(void __user *arg)
{
    struct paradise_hw_breakpoint_ctl_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) return -EFAULT;

    switch (cmd.action) {
    case HW_BP_ADD:
        return hwbp_add(cmd.pid, cmd.addr, cmd.type, cmd.len);
    case HW_BP_REMOVE:
        return hwbp_remove(cmd.pid, cmd.addr);
    default:
        paradise_err("hw_breakpoint_ctl: invalid action=%d\n", cmd.action);
        return -EINVAL;
    }
}

int do_hw_breakpoint_get_hits(void __user *arg)
{
    struct paradise_hw_breakpoint_get_hits_cmd cmd;
    void __user *uptr;
    void *staging;
    size_t want;
    size_t cap;
    size_t got;
    unsigned long flags;
    static const size_t HIT_SZ = sizeof(struct paradise_hw_breakpoint_hit_info);
    /* 单次 IOCTL 最多取多少条. 256 * 304 = 76 KiB kmalloc, 在限制内 (<128 KiB). */
    static const size_t MAX_PER_CALL = 256;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) return -EFAULT;

    uptr = (void __user *)cmd.buffer;
    want = cmd.count;

    if (!uptr || want == 0) {
        cmd.count = 0;
        return copy_to_user(arg, &cmd, sizeof(cmd)) ? -EFAULT : 0;
    }

    cap = (want < MAX_PER_CALL) ? want : MAX_PER_CALL;
    staging = kmalloc(cap * HIT_SZ, GFP_KERNEL);
    if (!staging) return -ENOMEM;

    /* spinlock 内只做定长 memcpy, 不做 copy_to_user (它可以 page fault → sleep). */
    got = 0;
    spin_lock_irqsave(&g_hits_lock, flags);
    while (got < cap && g_hits_count > 0) {
        memcpy((char *)staging + got * HIT_SZ,
               &g_hits_ring[g_hits_tail],
               HIT_SZ);
        g_hits_tail = (g_hits_tail + 1) % HWBP_RING_SIZE;
        g_hits_count--;
        got++;
    }
    spin_unlock_irqrestore(&g_hits_lock, flags);

    if (got > 0) {
        if (copy_to_user(uptr, staging, got * HIT_SZ)) {
            /* 数据已出 ring 但用户拷贝失败 → 这批数据丢. 客户端通过 -EFAULT
             * 知道失败, 不再依赖 cmd.count. */
            kfree(staging);
            return -EFAULT;
        }
    }
    kfree(staging);

    cmd.count = got;
    if (copy_to_user(arg, &cmd, sizeof(cmd))) return -EFAULT;
    return 0;
}

/* ============================================================================
 * 子系统生命周期
 * ========================================================================== */

int paradise_hwbp_init(void)
{
    g_hits_head = g_hits_tail = g_hits_count = 0;
    g_hits_dropped_total = 0;
    paradise_info("hwbp init: ring=%d entries (%zu KiB)\n",
                  HWBP_RING_SIZE,
                  (size_t)(HWBP_RING_SIZE * sizeof(struct paradise_hw_breakpoint_hit_info) / 1024));
    return 0;
}

void paradise_hwbp_exit(void)
{
    struct hwbp_entry *e, *tmp;
    struct hwbp_thread_bp *tb, *tb_tmp;

    mutex_lock(&g_hwbp_mutex);
    list_for_each_entry_safe(e, tmp, &g_hwbp_list, node) {
        list_del(&e->node);
        list_for_each_entry_safe(tb, tb_tmp, &e->thread_bps, node) {
            list_del(&tb->node);
            if (tb->bp) unregister_hw_breakpoint(tb->bp);
            kfree(tb);
        }
        kfree(e);
    }
    mutex_unlock(&g_hwbp_mutex);

    paradise_info("hwbp exit: cleaned, dropped_total=%llu\n",
                  (unsigned long long)g_hits_dropped_total);
}
