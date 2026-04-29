#ifndef PARADISE_HWBP_H
#define PARADISE_HWBP_H
/*
 * paradise_hwbp.h --- 硬件断点子系统 (ARM64)
 * ============================================================================
 * 功能:
 *   通过 Linux 内核 hw_breakpoint 子系统 (perf_event 的 BP 模式) 给指定用户
 *   态 VA 下硬件断点 (EXEC / WRITE / RW). 命中时把 pt_regs 抓出来塞 ring
 *   buffer, 用户态用 IOCTL 拉走.
 *
 * 设计:
 *   - 用 register_wide_hw_breakpoint (CPU-wide), 不需要给每个 tid 一一 attach,
 *     新 thread 自动覆盖.
 *   - handler 跑在 IRQ/NMI 上下文, 不能 sleep, 用 spinlock.
 *   - hits ring buffer 是静态固定大小 (HWBP_RING_SIZE), 满了丢老的保新的.
 *   - 多个 (pid, addr) 对可同时存在, 用链表管理.
 *
 * 客户端协议跟 S43/Tell解密/jni/src/Android_draw/绘图/Paradise.h 二进制兼容:
 *   IOCTL 25 = HW_BREAKPOINT_CTL  (struct paradise_hw_breakpoint_ctl_cmd)
 *   IOCTL 26 = HW_BREAKPOINT_GET_HITS (struct paradise_hw_breakpoint_get_hits_cmd)
 *   每条 hit  = struct paradise_hw_breakpoint_hit_info (304 字节, ARM64 LP64).
 * ============================================================================
 */

#include <asm/ptrace.h>
#include <linux/types.h>

/* ---- 协议常量 (跟客户端 Paradise.h 完全一致) ---- */

enum paradise_hwbp_action {
    HW_BP_ADD    = 1,
    HW_BP_REMOVE = 2,
};

enum paradise_hwbp_type {
    HW_BP_TYPE_EXECUTE = 0,
    HW_BP_TYPE_WRITE   = 1,
    HW_BP_TYPE_RW      = 2,
};

/* 必须跟 S43/绘图/Paradise.h 里的同名 struct 二进制兼容 (字段顺序/类型/对齐). */
struct paradise_hw_breakpoint_ctl_cmd {
    pid_t pid;        /* 目标进程 tgid */
    uintptr_t addr;   /* 用户态 VA, 已 untag */
    int action;       /* HW_BP_ADD / HW_BP_REMOVE */
    int type;         /* EXECUTE/WRITE/RW; REMOVE 时被忽略 */
    int len;          /* 1/2/4/8; REMOVE 时被忽略 */
};

struct paradise_hw_breakpoint_hit_info {
    pid_t pid;                  /* 命中时 current->tgid */
    uint64_t timestamp;         /* ktime_get_ns() */
    uintptr_t addr;             /* 注册时的 BP 地址 */
    struct user_pt_regs regs;   /* regs[31] + sp + pc + pstate, 35*8=280 字节 */
};

struct paradise_hw_breakpoint_get_hits_cmd {
    uintptr_t buffer;  /* 用户态 buffer (paradise_hw_breakpoint_hit_info[]) */
    size_t count;      /* in: 最多多少条; out: 实际拉到多少条 */
};

/* ---- 子系统生命周期 (在 paradise_init / paradise_exit 中调) ---- */
int  paradise_hwbp_init(void);
void paradise_hwbp_exit(void);

/* ---- IOCTL handler (在 paradise_ioctl.h 的 ioctl_handlers[] 注册) ---- */
int do_hw_breakpoint_ctl(void __user *arg);
int do_hw_breakpoint_get_hits(void __user *arg);

#endif /* PARADISE_HWBP_H */
