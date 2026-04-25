#include "paradise_ioctl.h"

#include <asm-generic/errno-base.h>

#include "paradise_utils.h"
#include "paradise_supercalls.h"
#include "paradise_gyro.h"

#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/smp.h>
#include <asm/memory.h>
#include <asm/pgtable-prot.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/cache.h>

#include "paradise_proc.h"

/*
 * Per-CPU PTE slot pool for lock-free physical page access.
 *
 * Each CPU gets its own vmalloc page whose PTE we hijack at runtime to
 * temporarily map arbitrary physical pages.  Selecting a slot with
 * get_cpu() (preempt_disable) guarantees exclusive access without any
 * mutex, spinlock or atomic — two threads on different CPUs never
 * touch the same slot.
 */

#define PARADISE_KBUF_ORDER  4      /* 2^4 pages = 64 KB batch buffer   */
#define PARADISE_KBUF_SIZE   (PAGE_SIZE << PARADISE_KBUF_ORDER)
#define PARADISE_SMALL_BUF   256    /* stack-resident fast-path buffer   */

static const uint64_t PTE_PHYS_FLAGS_CACHED =
    PTE_TYPE_PAGE | PTE_VALID | PTE_AF | PTE_SHARED |
    PTE_PXN | PTE_UXN | PTE_ATTRINDX(MT_NORMAL);

static const uint64_t PTE_PHYS_FLAGS_NC =
    PTE_TYPE_PAGE | PTE_VALID | PTE_AF | PTE_SHARED |
    PTE_PXN | PTE_UXN | PTE_ATTRINDX(MT_NORMAL_NC);

struct pte_physical_page_info {
    void          *base_address;
    pte_t         *pte_address;
    pte_t          orig_pte;      /* saved so vfree releases the right page */
    unsigned long  mapped_pfn;    /* PFN currently wired, 0 = none          */
    bool           is_nc;         /* true when slot is mapped non-cacheable  */
};

static struct pte_physical_page_info pte_pool[NR_CPUS];
static bool pte_pool_ready;
static DEFINE_MUTEX(pte_pool_init_mutex);

static inline pgd_t *paradise_get_kernel_pgd_base(void)
{
    uint64_t ttbr1;

    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    return (pgd_t *)phys_to_virt(ttbr1 & 0x0000FFFFFFFFF000ULL);
}

static int allocate_pte_slot(struct pte_physical_page_info *slot)
{
    uint64_t vaddr;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    if (in_atomic())
        return -EPERM;

    vaddr = (uint64_t)vmalloc(PAGE_SIZE);
    if (!vaddr)
        return -ENOMEM;

    memset((void *)vaddr, 0xAA, PAGE_SIZE);

    pgd = paradise_get_kernel_pgd_base() + pgd_index(vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto err;

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto err;

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto err;

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto err;

    if (pmd_leaf(*pmd))
        goto err;

    ptep = pte_offset_kernel(pmd, vaddr);
    if (!ptep)
        goto err;

    slot->base_address = (void *)vaddr;
    slot->pte_address  = ptep;
    slot->orig_pte     = READ_ONCE(*ptep);
    slot->mapped_pfn   = 0;
    return 0;

err:
    vfree((void *)vaddr);
    return -EFAULT;
}

static void free_pte_slot(struct pte_physical_page_info *slot)
{
    if (!slot->base_address)
        return;
    // 恢复原PTE并刷新
    set_pte(slot->pte_address, slot->orig_pte);
    flush_tlb_kernel_range((unsigned long)slot->base_address,
                           (unsigned long)slot->base_address + PAGE_SIZE);
    vfree(slot->base_address);
    memset(slot, 0, sizeof(*slot));
}

static int paradise_pte_pool_ensure(void)
{
    int ret = 0, i, n;

    if (likely(READ_ONCE(pte_pool_ready)))
        return 0;

    mutex_lock(&pte_pool_init_mutex);
    if (pte_pool_ready) {
        mutex_unlock(&pte_pool_init_mutex);
        return 0;
    }

    n = nr_cpu_ids;
    for (i = 0; i < n; i++) {
        ret = allocate_pte_slot(&pte_pool[i]);
        if (ret) {
            while (--i >= 0)
                free_pte_slot(&pte_pool[i]);
            break;
        }
    }

    if (!ret) {
        smp_wmb();
        WRITE_ONCE(pte_pool_ready, true);
    }
    mutex_unlock(&pte_pool_init_mutex);
    return ret;
}

void paradise_pte_phys_cleanup(void)
{
    int i;

    mutex_lock(&pte_pool_init_mutex);
    WRITE_ONCE(pte_pool_ready, false);
    smp_wmb();
    for (i = 0; i < NR_CPUS; i++)
        free_pte_slot(&pte_pool[i]);
    mutex_unlock(&pte_pool_init_mutex);
}

/*
 * Local-only TLB invalidation for a single kernel virtual address.
 * Uses Non-Shareable barriers — no cross-CPU IPI broadcast, purely
 * local micro-op.  Safe because the calling CPU is the only one that
 * ever accesses its own per-CPU PTE slot (preemption is disabled).
 */
static __always_inline void pte_flush_local(unsigned long va)
{
    dsb(nshst);
    asm volatile("tlbi vaale1, %0"
                 :: "r"((va >> 12) & ((1ULL << 44) - 1))
                 : "memory");
    dsb(nsh);
    isb();
}

/*
 * Clean-and-Invalidate data cache lines by VA to Point of Coherency.
 * Flushes dirty cache lines from ALL CPUs' caches to physical memory
 * and invalidates them, so subsequent NC reads see fresh data and
 * NC writes are immediately visible to the target process.
 */
static __always_inline void dcache_civac_line(const void *addr)
{
    asm volatile("dc civac, %0" :: "r"(addr) : "memory");
}

static __always_inline void dcache_civac_range(const void *addr, size_t len)
{
    unsigned long p   = (unsigned long)addr & ~(L1_CACHE_BYTES - 1);
    unsigned long end = (unsigned long)addr + len;

    for (; p < end; p += L1_CACHE_BYTES)
        dcache_civac_line((void *)p);
    dsb(ish);
}

/*
 * Wire a PTE slot to @pfn with the given attribute flags.
 * Skips the TLB flush when PFN and attribute type already match.
 */
static __always_inline void pte_wire(struct pte_physical_page_info *slot,
                                     unsigned long pfn, uint64_t flags,
                                     bool nc)
{
    if (slot->mapped_pfn != pfn || slot->is_nc != nc) {
        WRITE_ONCE(*(slot->pte_address),
                   pfn_pte(pfn, __pgprot(flags)));
        pte_flush_local((unsigned long)slot->base_address);
        slot->mapped_pfn = pfn;
        slot->is_nc      = nc;
    }
}

/*
 * Non-cacheable remap for READS.
 *
 *  1. Map the page as MT_NORMAL (cached)
 *  2. dc civac the target range — cleans dirty cache lines from ALL CPUs
 *     to physical memory and invalidates them
 *  3. Remap as MT_NORMAL_NC — subsequent memcpy reads bypass all caches
 *
 * MUST be called with preemption disabled (between get_cpu / put_cpu).
 */
static __always_inline void *pte_remap_nc(
    struct pte_physical_page_info *slot,
    phys_addr_t paddr, size_t size)
{
    unsigned long pfn = __phys_to_pfn(paddr);
    void *ptr;

    if (unlikely(!pfn_valid(pfn)))
        return ERR_PTR(-EFAULT);
    if (unlikely(((paddr & ~PAGE_MASK) + size) > PAGE_SIZE))
        return ERR_PTR(-EINVAL);

    ptr = (uint8_t *)slot->base_address + (paddr & ~PAGE_MASK);

    pte_wire(slot, pfn, PTE_PHYS_FLAGS_CACHED, false);
    dcache_civac_range(ptr, size);

    pte_wire(slot, pfn, PTE_PHYS_FLAGS_NC, true);
    return ptr;
}

/*
 * Non-cacheable remap for WRITES.
 * Maps as MT_NORMAL_NC so the caller's memcpy goes straight to RAM.
 *
 * MUST be called with preemption disabled (between get_cpu / put_cpu).
 */
static __always_inline void *pte_remap_nc_write(
    struct pte_physical_page_info *slot,
    phys_addr_t paddr, size_t size)
{
    unsigned long pfn = __phys_to_pfn(paddr);

    if (unlikely(!pfn_valid(pfn)))
        return ERR_PTR(-EFAULT);
    if (unlikely(((paddr & ~PAGE_MASK) + size) > PAGE_SIZE))
        return ERR_PTR(-EINVAL);

    pte_wire(slot, pfn, PTE_PHYS_FLAGS_NC, true);
    return (uint8_t *)slot->base_address + (paddr & ~PAGE_MASK);
}

/*
 * Post-write cache invalidation.
 * Briefly switches back to cached mapping and dc civac the written range
 * so every other CPU's stale cache lines are invalidated — the target
 * process will re-read from physical memory on next access.
 *
 * MUST be called with preemption disabled, right after the write memcpy.
 */
static __always_inline void pte_flush_after_write(
    struct pte_physical_page_info *slot,
    phys_addr_t paddr, size_t size)
{
    unsigned long pfn = __phys_to_pfn(paddr);
    void *ptr = (uint8_t *)slot->base_address + (paddr & ~PAGE_MASK);

    pte_wire(slot, pfn, PTE_PHYS_FLAGS_CACHED, false);
    dcache_civac_range(ptr, size);

    pte_wire(slot, pfn, PTE_PHYS_FLAGS_NC, true);
}

// 无锁遍历
#ifndef pud_sect
#define pud_sect(pud) (0)
#endif

static int lockfree_va_to_pa(pgd_t *pgd_base, uintptr_t va,
                              phys_addr_t *pa_out, size_t *contig_out)
{
    pgd_t pgd_e;
    p4d_t *p4dp, p4d_e;
    pud_t *pudp, pud_e;
    pmd_t *pmdp, pmd_e;
    pte_t *ptep, pte_e;
    size_t off;

    pgd_e = READ_ONCE(*(pgd_base + pgd_index(va)));
    if (pgd_none(pgd_e) || pgd_bad(pgd_e))
        return -EFAULT;

    p4dp = p4d_offset(&pgd_e, va);
    p4d_e = READ_ONCE(*p4dp);
    if (p4d_none(p4d_e) || p4d_bad(p4d_e))
        return -EFAULT;

    pudp = pud_offset(&p4d_e, va);
    pud_e = READ_ONCE(*pudp);
    if (pud_none(pud_e))
        return -EFAULT;

    if (pud_sect(pud_e)) {
        off = va & (PUD_SIZE - 1);
        *pa_out = ((phys_addr_t)pud_pfn(pud_e) << PAGE_SHIFT) | off;
        *contig_out = PUD_SIZE - off;
        return 0;
    }

    if (pud_bad(pud_e))
        return -EFAULT;

    pmdp = pmd_offset(&pud_e, va);
    pmd_e = READ_ONCE(*pmdp);
    if (pmd_none(pmd_e))
        return -EFAULT;

    if (pmd_leaf(pmd_e)) {
        off = va & (PMD_SIZE - 1);
        *pa_out = ((phys_addr_t)pmd_pfn(pmd_e) << PAGE_SHIFT) | off;
        *contig_out = PMD_SIZE - off;
        return 0;
    }

    if (pmd_bad(pmd_e))
        return -EFAULT;

    ptep = pte_offset_kernel(&pmd_e, va);
    pte_e = READ_ONCE(*ptep);
    if (pte_none(pte_e) || !pte_present(pte_e))
        return -EFAULT;

    off = va & (PAGE_SIZE - 1);
    *pa_out = (pte_pfn(pte_e) << PAGE_SHIFT) | off;
    *contig_out = PAGE_SIZE - off;
    return 0;
}

int do_read_physical_memory(void __user *arg)
{
    struct paradise_memory_rw_cmd cmd;
    struct pid *pid_s;
    struct task_struct *task;
    struct mm_struct *mm;
    pgd_t *pgd_base;
    uint8_t small_buf[PARADISE_SMALL_BUF];
    void *kbuf;
    size_t kbuf_size, remaining, cur_off, buf_used;
    uintptr_t cur_va;
    bool kbuf_heap = false;
    int ret, cpu;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    if (cmd.size == 0)
        return -EINVAL;

    pid_s = find_get_pid(cmd.pid);
    if (!pid_s)
        return -ESRCH;
    task = get_pid_task(pid_s, PIDTYPE_PID);
    put_pid(pid_s);
    if (!task)
        return -ESRCH;
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -ESRCH;

    pgd_base = mm->pgd;

    {
        phys_addr_t first_pa;
        size_t dummy;

        ret = lockfree_va_to_pa(pgd_base, cmd.src_va, &first_pa, &dummy);
        if (ret < 0) {
            mmput(mm);
            return ret;
        }
        cmd.phy_addr = (uintptr_t)first_pa;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        mmput(mm);
        return -EFAULT;
    }

    ret = paradise_pte_pool_ensure();
    if (ret) {
        mmput(mm);
        return ret;
    }

    /*
     小批量读取
     */
    if (cmd.size <= PARADISE_SMALL_BUF) {
        kbuf      = small_buf;
        kbuf_size = cmd.size;
    } else {
        kbuf_size = min_t(size_t, PARADISE_KBUF_SIZE, cmd.size);
        kbuf = kmalloc(kbuf_size, GFP_KERNEL);
        if (!kbuf) {
            kbuf_size = PAGE_SIZE;
            kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
            if (!kbuf) {
                mmput(mm);
                return -ENOMEM;
            }
        }
        kbuf_heap = true;
    }

    remaining = cmd.size;
    cur_va    = cmd.src_va;
    cur_off   = 0;
    buf_used  = 0;

    while (remaining > 0) {
        phys_addr_t pa;
        size_t contig, contig_todo;

        ret = lockfree_va_to_pa(pgd_base, cur_va, &pa, &contig);
        if (ret < 0)
            goto out;

        contig_todo = min_t(size_t, remaining, contig);
        while (contig_todo > 0) {
            size_t chunk = min_t(size_t,
                                 PAGE_SIZE - (pa & (PAGE_SIZE - 1)),
                                 contig_todo);
            void *mapped;

            /* Flush the batch buffer before it overflows */
            if (buf_used + chunk > kbuf_size) {
                if (copy_to_user(
                        (void __user *)(cmd.dst_va + cur_off - buf_used),
                        kbuf, buf_used)) {
                    ret = -EFAULT;
                    goto out;
                }
                buf_used = 0;
            }

            cpu = get_cpu();
            mapped = pte_remap_nc(&pte_pool[cpu], pa, chunk);
            if (IS_ERR(mapped)) {
                put_cpu();
                ret = PTR_ERR(mapped);
                goto out;
            }
            memcpy((uint8_t *)kbuf + buf_used, mapped, chunk);
            put_cpu();

            buf_used    += chunk;
            pa          += chunk;
            cur_va      += chunk;
            cur_off     += chunk;
            remaining   -= chunk;
            contig_todo -= chunk;
        }
    }

    // 刷新剩余数据
    if (buf_used > 0) {
        if (copy_to_user(
                (void __user *)(cmd.dst_va + cur_off - buf_used),
                kbuf, buf_used)) {
            ret = -EFAULT;
            goto out;
        }
    }
    ret = 0;

out:
    if (kbuf_heap)
        kfree(kbuf);
    mmput(mm);
    return ret;
}

int do_get_module_base(void __user* arg) {
    struct paradise_get_module_base_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    uintptr_t base = 0, end = 0;

    if (!get_module_bounds(cmd.pid, cmd.name, cmd.vm_flag, &base, &end)) {
        return -ENAVAIL;
    }

    cmd.base = base;
    cmd.end = end;
    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_find_process(void __user* arg) {
    struct paradise_find_proc_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    cmd.pid = find_process_by_name(cmd.name);
    if (cmd.pid == 0) {
        return -ENAVAIL;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_write_physical_memory(void __user *arg)
{
    struct paradise_memory_rw_cmd cmd;
    struct pid *pid_s;
    struct task_struct *task;
    struct mm_struct *mm;
    pgd_t *pgd_base;
    uint8_t small_buf[PARADISE_SMALL_BUF];
    void *kbuf;
    size_t kbuf_size, remaining, cur_off;
    uintptr_t cur_va;
    bool kbuf_heap = false;
    int ret, cpu;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    if (cmd.size == 0)
        return -EINVAL;

    pid_s = find_get_pid(cmd.pid);
    if (!pid_s)
        return -ESRCH;
    task = get_pid_task(pid_s, PIDTYPE_PID);
    put_pid(pid_s);
    if (!task)
        return -ESRCH;
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -ESRCH;

    pgd_base = mm->pgd;

    {
        phys_addr_t first_pa;
        size_t dummy;

        ret = lockfree_va_to_pa(pgd_base, cmd.dst_va, &first_pa, &dummy);
        if (ret < 0) {
            mmput(mm);
            return ret;
        }
        cmd.phy_addr = (uintptr_t)first_pa;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        mmput(mm);
        return -EFAULT;
    }

    ret = paradise_pte_pool_ensure();
    if (ret) {
        mmput(mm);
        return ret;
    }

    if (cmd.size <= PARADISE_SMALL_BUF) {
        kbuf      = small_buf;
        kbuf_size = cmd.size;
    } else {
        kbuf_size = min_t(size_t, PARADISE_KBUF_SIZE, cmd.size);
        kbuf = kmalloc(kbuf_size, GFP_KERNEL);
        if (!kbuf) {
            kbuf_size = PAGE_SIZE;
            kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
            if (!kbuf) {
                mmput(mm);
                return -ENOMEM;
            }
        }
        kbuf_heap = true;
    }

    remaining = cmd.size;
    cur_va    = cmd.dst_va;
    cur_off   = 0;

    while (remaining > 0) {
        /*
         * Pre-load a full batch from userspace in one shot, then
         * scatter-write it to the target's physical pages.  This
         * cuts copy_from_user calls by up to 16× for large writes.
         */
        size_t preload = min_t(size_t, remaining, kbuf_size);
        size_t kbuf_pos = 0;

        if (copy_from_user(kbuf,
                           (void __user *)(cmd.src_va + cur_off),
                           preload)) {
            ret = -EFAULT;
            goto out;
        }

        while (kbuf_pos < preload) {
            phys_addr_t pa;
            size_t contig, contig_todo;

            ret = lockfree_va_to_pa(pgd_base, cur_va, &pa, &contig);
            if (ret < 0)
                goto out;

            contig_todo = min_t(size_t, preload - kbuf_pos, contig);
            while (contig_todo > 0) {
                size_t chunk = min_t(size_t,
                                     PAGE_SIZE - (pa & (PAGE_SIZE - 1)),
                                     contig_todo);
                void *mapped;

                cpu = get_cpu();
                mapped = pte_remap_nc_write(&pte_pool[cpu], pa, chunk);
                if (IS_ERR(mapped)) {
                    put_cpu();
                    ret = PTR_ERR(mapped);
                    goto out;
                }
                memcpy(mapped, (uint8_t *)kbuf + kbuf_pos, chunk);
                pte_flush_after_write(&pte_pool[cpu], pa, chunk);
                put_cpu();

                kbuf_pos    += chunk;
                pa          += chunk;
                cur_va      += chunk;
                cur_off     += chunk;
                remaining   -= chunk;
                contig_todo -= chunk;
            }
        }
    }

    ret = 0;
out:
    if (kbuf_heap)
        kfree(kbuf);
    mmput(mm);
    return ret;
}

int do_is_process_alive(void __user* arg) {
    struct paradise_is_proc_alive_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    cmd.alive = is_pid_alive(cmd.pid);

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

/* ===== Hidden process tracking infrastructure ===== */

struct paradise_hidden_proc {
    struct list_head list;
    pid_t pid;
    struct task_struct *task;     // ref-counted reference
    bool tasks_unlinked;         // unlinked from task->tasks list
    bool proc_mounted;           // tmpfs over /proc/<pid>
    bool cgroup_mounted;         // tmpfs over /sys/fs/cgroup/uid_0/pid_<pid>
    bool kgsl_mounted;           // tmpfs over /sys/devices/virtual/kgsl/kgsl/proc/<pid>
};

static LIST_HEAD(hidden_proc_list);
static DEFINE_SPINLOCK(hidden_proc_lock);

// Resolved kernel symbols for hide operations (resolved once, cached)
static int (*kfn_path_mount)(const char *, struct path *,
                              const char *, unsigned long, void *) = NULL;
static int (*kfn_path_umount)(struct path *, int) = NULL;
static int (*kfn_kern_path)(const char *, unsigned int, struct path *) = NULL;
static void (*kfn_path_put)(struct path *) = NULL;
static rwlock_t *kfn_tasklist_lock = NULL;
static struct task_struct *kfn_init_task = NULL;

static int resolve_hide_symbols(void)
{
    if (!kfn_path_mount)
        kfn_path_mount = (void *)kallsyms_lookup_name_ex("path_mount");
    if (!kfn_path_umount)
        kfn_path_umount = (void *)kallsyms_lookup_name_ex("path_umount");
    if (!kfn_kern_path)
        kfn_kern_path = (void *)kallsyms_lookup_name_ex("kern_path");
    if (!kfn_path_put)
        kfn_path_put = (void *)kallsyms_lookup_name_ex("path_put");
    if (!kfn_tasklist_lock)
        kfn_tasklist_lock = (void *)kallsyms_lookup_name_ex("tasklist_lock");
    if (!kfn_init_task)
        kfn_init_task = (void *)kallsyms_lookup_name_ex("init_task");

    if (!kfn_path_mount || !kfn_path_umount || !kfn_kern_path || !kfn_path_put) {
        paradise_err("hide: failed to resolve required path symbols\n");
        return -ENOENT;
    }
    if (!kfn_tasklist_lock || !kfn_init_task)
        paradise_warn("hide: tasklist_lock/init_task not found, task list unlink disabled\n");

    return 0;
}

// Mount tmpfs over target_path. Returns 0 on success, 1 if path doesn't exist, <0 on error.
// path_mount writes ((char*)data_page)[PAGE_SIZE-1] = 0, so data_page MUST be a full page.
static int hide_mount_tmpfs(const char *target_path)
{
    struct path path;
    char *mount_opts;
    int ret;

    ret = kfn_kern_path(target_path, LOOKUP_FOLLOW, &path);
    if (ret)
        return 1; // path doesn't exist, skip silently

    mount_opts = (char *)__get_free_page(GFP_KERNEL);
    if (!mount_opts) {
        kfn_path_put(&path);
        return -ENOMEM;
    }
    memset(mount_opts, 0, PAGE_SIZE);
    strcpy(mount_opts, "size=0,mode=0555");

    // MS_NOSUID(2) | MS_NODEV(4) | MS_NOEXEC(8) | MS_SILENT(1<<15)
    ret = kfn_path_mount("tmpfs", &path, "tmpfs",
                          (2 | 4 | 8 | (1 << 15)),
                          mount_opts);
    free_page((unsigned long)mount_opts);
    kfn_path_put(&path);

    if (ret)
        paradise_warn("hide: mount over %s failed: %d\n", target_path, ret);
    return ret;
}

// 从target_path卸载tmpfs
// path_umount成功后会消耗path引用
static void hide_umount_path(const char *target_path)
{
    struct path path;
    int ret;

    ret = kfn_kern_path(target_path, LOOKUP_FOLLOW, &path);
    if (ret)
        return;

    ret = kfn_path_umount(&path, MNT_DETACH);
    if (ret)
        kfn_path_put(&path);
}

static struct paradise_hidden_proc *find_hidden_proc_locked(pid_t pid)
{
    struct paradise_hidden_proc *entry;
    list_for_each_entry(entry, &hidden_proc_list, list) {
        if (entry->pid == pid)
            return entry;
    }
    return NULL;
}

/* ===== Arbitrary path hide (tmpfs overlay, same as per-path hides in hide process) ===== */

struct paradise_hidden_path {
    struct list_head list;
    char path[PARADISE_HIDE_PATH_MAX];
    bool mounted;
};

static LIST_HEAD(hidden_path_list);
static DEFINE_SPINLOCK(hidden_path_lock);

static struct paradise_hidden_path *find_hidden_path_locked(const char *path)
{
    struct paradise_hidden_path *entry;

    list_for_each_entry(entry, &hidden_path_list, list) {
        if (!strcmp(entry->path, path))
            return entry;
    }
    return NULL;
}

int do_hide_path(void __user *arg)
{
    struct paradise_hide_path_cmd cmd;
    struct paradise_hidden_path *entry;
    char kpath[PARADISE_HIDE_PATH_MAX];
    size_t len;
    int ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    cmd.path[PARADISE_HIDE_PATH_MAX - 1] = '\0';
    len = strnlen(cmd.path, PARADISE_HIDE_PATH_MAX);
    if (len == 0 || len >= PARADISE_HIDE_PATH_MAX)
        return -EINVAL;
    if (cmd.path[0] != '/')
        return -EINVAL;

    memcpy(kpath, cmd.path, len + 1);

    ret = resolve_hide_symbols();
    if (ret)
        return ret;

    if (cmd.hide) {
        spin_lock(&hidden_path_lock);
        if (find_hidden_path_locked(kpath)) {
            spin_unlock(&hidden_path_lock);
            return 0;
        }
        spin_unlock(&hidden_path_lock);

        ret = hide_mount_tmpfs(kpath);
        if (ret == 1)
            return -ENOENT;
        if (ret < 0)
            return ret;

        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            hide_umount_path(kpath);
            return -ENOMEM;
        }
        memcpy(entry->path, kpath, len + 1);
        entry->mounted = true;
        INIT_LIST_HEAD(&entry->list);

        spin_lock(&hidden_path_lock);
        if (find_hidden_path_locked(kpath)) {
            spin_unlock(&hidden_path_lock);
            hide_umount_path(kpath);
            kfree(entry);
            return 0;
        }
        list_add(&entry->list, &hidden_path_list);
        spin_unlock(&hidden_path_lock);

        paradise_info("hid path %s\n", kpath);
        return 0;
    }

    spin_lock(&hidden_path_lock);
    entry = find_hidden_path_locked(kpath);
    if (!entry) {
        spin_unlock(&hidden_path_lock);
        paradise_warn("hide_path: %s not in hidden list\n", kpath);
        return -ENOENT;
    }
    list_del(&entry->list);
    spin_unlock(&hidden_path_lock);

    if (entry->mounted)
        hide_umount_path(entry->path);
    kfree(entry);

    paradise_info("unhid path %s\n", kpath);
    return 0;
}

int do_hide_process(void __user* arg) {
    struct paradise_hide_proc_cmd cmd;
    struct task_struct *task;
    struct paradise_hidden_proc *entry;
    char path_buf[64];
    int ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    ret = resolve_hide_symbols();
    if (ret)
        return ret;

    if (cmd.hide) {
        /* ===== HIDE ===== */

        // 检查是否已隐藏
        spin_lock(&hidden_proc_lock);
        if (find_hidden_proc_locked(cmd.pid)) {
            spin_unlock(&hidden_proc_lock);
            return 0; // 已隐藏
        }
        spin_unlock(&hidden_proc_lock);

        // 验证目标进程存在
        task = get_target_task(cmd.pid);
        if (!task)
            return -ESRCH;

        // 分配跟踪项
        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            put_task_struct(task);
            return -ENOMEM;
        }
        entry->pid = cmd.pid;
        entry->task = task; // 转移task引用

        // 设置PF_INVISIBLE标志
        task->flags |= PF_INVISIBLE;

        // 解绑tasklist
        if (kfn_tasklist_lock && kfn_init_task) {
            write_lock_irq(kfn_tasklist_lock);
            list_del_init(&task->tasks);
            write_unlock_irq(kfn_tasklist_lock);
            entry->tasks_unlinked = true;
        }

        // 挂载/proc/<pid>
        snprintf(path_buf, sizeof(path_buf), "/proc/%d", cmd.pid);
        if (hide_mount_tmpfs(path_buf) == 0)
            entry->proc_mounted = true;

        // 挂载cgroup PID路径
        snprintf(path_buf, sizeof(path_buf), "/sys/fs/cgroup/uid_0/pid_%d", cmd.pid);
        if (hide_mount_tmpfs(path_buf) == 0)
            entry->cgroup_mounted = true;

        // 挂载骁龙KGSL PID路径
        snprintf(path_buf, sizeof(path_buf),
                 "/sys/devices/virtual/kgsl/kgsl/proc/%d", cmd.pid);
        if (hide_mount_tmpfs(path_buf) == 0)
            entry->kgsl_mounted = true;

        // 添加跟踪
        INIT_LIST_HEAD(&entry->list);
        spin_lock(&hidden_proc_lock);
        list_add(&entry->list, &hidden_proc_list);
        spin_unlock(&hidden_proc_lock);

        paradise_info("hid pid %d (unlinked=%d proc=%d cgroup=%d kgsl=%d)\n",
                      cmd.pid, entry->tasks_unlinked, entry->proc_mounted,
                      entry->cgroup_mounted, entry->kgsl_mounted);
        return 0;

    } else {
        /* ===== 取消隐藏 ===== */

        // 查找并移除跟踪项
        spin_lock(&hidden_proc_lock);
        entry = find_hidden_proc_locked(cmd.pid);
        if (!entry) {
            spin_unlock(&hidden_proc_lock);
            paradise_warn("hide: pid %d not in hidden list\n", cmd.pid);
            return -ESRCH;
        }
        list_del(&entry->list);
        spin_unlock(&hidden_proc_lock);

        task = entry->task;

        // 清除PF_INVISIBLE标志
        task->flags &= ~PF_INVISIBLE;

        // 重新绑定tasklist
        if (entry->tasks_unlinked && kfn_tasklist_lock && kfn_init_task) {
            write_lock_irq(kfn_tasklist_lock);
            if (pid_alive(task))
                list_add_tail(&task->tasks, &kfn_init_task->tasks);
            write_unlock_irq(kfn_tasklist_lock);
        }

        // 卸载/proc/<pid>
        if (entry->proc_mounted) {
            snprintf(path_buf, sizeof(path_buf), "/proc/%d", cmd.pid);
            hide_umount_path(path_buf);
        }

        // 卸载cgroup路径
        if (entry->cgroup_mounted) {
            snprintf(path_buf, sizeof(path_buf), "/sys/fs/cgroup/uid_0/pid_%d", cmd.pid);
            hide_umount_path(path_buf);
        }

        // 卸载骁龙KGSL路径
        if (entry->kgsl_mounted) {
            snprintf(path_buf, sizeof(path_buf),
                     "/sys/devices/virtual/kgsl/kgsl/proc/%d", cmd.pid);
            hide_umount_path(path_buf);
        }

        // 释放task引用并释放跟踪项
        put_task_struct(task);
        kfree(entry);

        paradise_info("unhid pid %d\n", cmd.pid);
        return 0;
    }
}

int do_list_processes(void __user* arg) {
    struct paradise_list_processes_cmd cmd;
    struct task_struct* task;
    u8* kernel_bitmap;
    size_t process_count = 0;
    int ret = 0;

    // Copy command from userspace
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    // Validate bitmap size (must be at least 8192 bytes for PID 0-65535)
    if (cmd.bitmap_size < 8192) {
        paradise_warn("bitmap size too small: %zu (minimum 8192)\n", cmd.bitmap_size);
        return -EINVAL;
    }

    // Allocate kernel bitmap buffer
    kernel_bitmap = kzalloc(cmd.bitmap_size, GFP_KERNEL);
    if (!kernel_bitmap) {
        paradise_err("failed to allocate kernel bitmap\n");
        return -ENOMEM;
    }

    // Iterate through all processes and set corresponding bits
    rcu_read_lock();
    for_each_process(task) {
        pid_t pid = task->pid;
        
        // Check if PID is within bitmap range
        if (pid >= 0 && pid < (cmd.bitmap_size * 8)) {
            size_t byte_index = pid / 8;
            size_t bit_index = pid % 8;
            
            // Set the bit
            kernel_bitmap[byte_index] |= (1 << bit_index);
            process_count++;
        }
    }
    rcu_read_unlock();

    // Copy bitmap to userspace
    if (copy_to_user(cmd.bitmap, kernel_bitmap, cmd.bitmap_size)) {
        ret = -EFAULT;
        goto out_free;
    }

    // Update process count and copy back to userspace
    cmd.process_count = process_count;
    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        ret = -EFAULT;
        goto out_free;
    }

    paradise_info("listed %zu processes in bitmap\n", process_count);

out_free:
    kfree(kernel_bitmap);
    return ret;
}