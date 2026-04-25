#include "paradise_utils.h"

#include <linux/hugetlb.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/pgtable.h>
#else
#include <asm/pgtable.h>
#endif
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/kernel.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/page_pinner.h>
/*
 * 某些 Android 12/5.10 GKI 未导出 page_pinner_inited，但新版头文件会声明
 * (类型为 struct static_key_false)，导致模块加载 Unknown symbol。
 * 用同类型的弱符号兜底；若运行内核提供强符号，强符号会覆盖该弱符号。
 */
struct static_key_false page_pinner_inited __weak;
#endif

#include "hijack_arm64.h"
#include "linux/pid.h"

#ifdef CONFIG_CFI_CLANG
#define NO_CFI __nocfi
#else
#define NO_CFI
#endif

static int paradise_flip_open(const char* filename, int flags, umode_t mode, struct file** f) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    *f = filp_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#else
    static struct file* (*reserve_flip_open)(const char* filename, int flags, umode_t mode) = NULL;

    if (reserve_flip_open == NULL) {
        reserve_flip_open =
            (struct file * (*)(const char* filename, int flags, umode_t mode)) kallsyms_lookup_name_ex("filp_open");
        if (reserve_flip_open == NULL) {
            return -1;
        }
    }

    *f = reserve_flip_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#endif
}

static int paradise_flip_close(struct file** f, fl_owner_t id) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    filp_close(*f, id);
    return 0;
#else
    static struct file* (*reserve_flip_close)(struct file** f, fl_owner_t id) = NULL;

    if (reserve_flip_close == NULL) {
        reserve_flip_close = (struct file * (*)(struct file * *f, fl_owner_t id)) kallsyms_lookup_name_ex("filp_close");
        if (reserve_flip_close == NULL) {
            return -1;
        }
    }

    reserve_flip_close(f, id);
    return 0;
#endif
}

bool is_file_exist(const char* filename) {
    struct file* fp;

    if (paradise_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            paradise_flip_close(&fp, NULL);
            return true;
        }
        return false;
    }

    //    // int kern_path(const char *name, unsigned int flags, struct path *path)
    //    struct path path;
    //    if (kern_path(filename, LOOKUP_FOLLOW, &path) == 0) {
    //        return true;
    //    }

    return false;
}

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static unsigned long NO_CFI call_kln(kallsyms_lookup_name_t f, const char *n) {
    return f(n);
}

__attribute__((no_sanitize("cfi"))) unsigned long kallsyms_lookup_name_ex(const char* name) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    static kallsyms_lookup_name_t lookup_name = NULL;
    if (lookup_name == NULL) {
        struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};

        if (register_kprobe(&kp) < 0) {
            return 0;
        }

        lookup_name = (kallsyms_lookup_name_t)kp.addr;
        unregister_kprobe(&kp);

        if (lookup_name == NULL) {
            paradise_err("kallsyms_lookup_name not found\n");
            return 0;
        }
        paradise_info("kallsyms_lookup_name_ex found at %p\n", lookup_name);
    }

    return call_kln(lookup_name, name);
#else
    return kallsyms_lookup_name(name);
#endif
}

struct task_struct* get_target_task(pid_t pid) {
    struct pid* pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return NULL;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        return NULL;
    }

    return task;
}

int disable_kprobe_blacklist(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    // For newer kernels, kprobe_blacklist_entry is defined in kprobes.h
    struct kprobe_blacklist_entry* ent;
    struct list_head* kprobe_blacklist = (struct list_head*)kallsyms_lookup_name_ex("kprobe_blacklist");
    if (!kprobe_blacklist) {
        paradise_err("kprobe_blacklist not found\n");
        return -ENOENT;
    }

    int count = 0;
    list_for_each_entry(ent, kprobe_blacklist, list) {
        if (!ent || ent->start_addr == 0 || ent->end_addr == 0) {
            continue;
        }
        count++;
        ent->start_addr = 0;
        ent->end_addr = 0;
    }

    paradise_info("Disabled %d kprobe blacklist entries\n", count);

    return 0;
#else
    // For older kernels (5.10-5.15), define the structure locally
    // This structure may not be in public headers in older kernels
    struct kprobe_blacklist_entry_local {
        struct list_head list;
        unsigned long start_addr;
        unsigned long end_addr;
    };
    
    struct kprobe_blacklist_entry_local* ent;
    struct list_head* kprobe_blacklist = (struct list_head*)kallsyms_lookup_name_ex("kprobe_blacklist");
    if (!kprobe_blacklist) {
        paradise_err("kprobe_blacklist not found\n");
        return -ENOENT;
    }

    int count = 0;
    list_for_each_entry(ent, kprobe_blacklist, list) {
        if (!ent || ent->start_addr == 0 || ent->end_addr == 0) {
            continue;
        }
        count++;
        ent->start_addr = 0;
        ent->end_addr = 0;
    }

    paradise_info("Disabled %d kprobe blacklist entries\n", count);

    return 0;
#endif
}

void compare_pt_regs(struct pt_regs* regs1, struct pt_regs* regs2) {
#if CONFIG_COMPARE_PT_REGS == 1
    paradise_info("==> Comparing pt_regs:\n");

    for (int i = 0; i < 31; ++i) {
        if (regs1->regs[i] != regs2->regs[i]) {
            paradise_info("reg[%d] changed from %llx to %llx\n", i, regs1->regs[i], regs2->regs[i]);
        }
    }

    if (regs1->sp != regs2->sp) {
        paradise_info("sp changed from %llx to %llx\n", regs1->sp, regs2->sp);
    }

    if (regs1->pc != regs2->pc) {
        paradise_info("pc changed from %llx to %llx\n", regs1->pc, regs2->pc);
    }

    if (regs1->pstate != regs2->pstate) {
        paradise_info("pstate changed from %llx to %llx\n", regs1->pstate, regs2->pstate);
    }

    if (regs1->sdei_ttbr1 != regs2->sdei_ttbr1) {
        paradise_info("sdei_ttbr1 changed from %llx to %llx\n", regs1->sdei_ttbr1, regs2->sdei_ttbr1);
    }

    if (regs1->pmr_save != regs2->pmr_save) {
        paradise_info("pmr_save changed from %llx to %llx\n", regs1->pmr_save, regs2->pmr_save);
    }

    if (regs1->stackframe[0] != regs2->stackframe[0] || regs1->stackframe[1] != regs2->stackframe[1]) {
        paradise_info("stackframe changed from [%llx, %llx] to [%llx, %llx]\n", regs1->stackframe[0], regs1->stackframe[1],
                 regs2->stackframe[0], regs2->stackframe[1]);
    }
#endif
}

void compare_task_struct(struct task_struct* task1, struct task_struct* task2) {
#if CONFIG_COMPARE_TASK == 1
    paradise_info("==> Comparing task_struct:\n");
#ifdef CONFIG_THREAD_INFO_IN_TASK
    if (task1->thread_info.flags != task2->thread_info.flags) {
        paradise_info("thread_info.flags changed from %lx to %lx\n", task1->thread_info.flags, task2->thread_info.flags);
    }

    if (task1->thread_info.cpu != task2->thread_info.cpu) {
        paradise_info("thread_info.cpu changed from %d to %d\n", task1->thread_info.cpu, task2->thread_info.cpu);
    }
#endif

    if (task1->__state != task2->__state) {
        paradise_info("__state changed from %u to %u\n", task1->__state, task2->__state);
    }

    if (task1->stack != task2->stack) {
        paradise_info("stack pointer changed from %p to %p\n", task1->stack, task2->stack);
    }

    if (task1->flags != task2->flags) {
        paradise_info("flags changed from %u to %u\n", task1->flags, task2->flags);
    }

    if (task1->ptrace != task2->ptrace) {
        paradise_info("ptrace changed from %u to %u\n", task1->ptrace, task2->ptrace);
    }

    if (task1->pid != task2->pid) {
        paradise_info("pid changed from %d to %d\n", task1->pid, task2->pid);
    }

    if (task1->tgid != task2->tgid) {
        paradise_info("tgid changed from %d to %d\n", task1->tgid, task2->tgid);
    }
#endif
}

int get_module_bounds(pid_t pid, char* name, int vm_flag, uintptr_t* base_out, uintptr_t* end_out) {
    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;
    struct vm_area_struct* vma;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif
    struct dentry* dentry;
    struct dentry* matched_dentry = NULL;
    size_t name_len, dname_len;
    uintptr_t base = 0;
    uintptr_t end = 0;

    if (!base_out || !end_out) {
        paradise_err("get_module_bounds: null output pointer\n");
        return 0;
    }

    name_len = strlen(name);
    if (name_len == 0) {
        paradise_err("module name is empty\n");
        return 0;
    }

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        paradise_err("failed to find pid_struct\n");
        return 0;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        paradise_err("failed to get task from pid_struct\n");
        return 0;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        paradise_err("failed to get mm from task\n");
        return 0;
    }

    MM_READ_LOCK(mm)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (!vma->vm_file) {
            continue;
        }
        if (vm_flag && !(vma->vm_flags & vm_flag)) {
            continue;
        }
        dentry = vma->vm_file->f_path.dentry;
        dname_len = dentry->d_name.len;
        if (memcmp(dentry->d_name.name, name, min(name_len, dname_len))) {
            continue;
        }
        if (!matched_dentry) {
            matched_dentry = dentry;
            base = vma->vm_start;
            end = vma->vm_end;
        } else if (matched_dentry == dentry) {
            base = min(base, vma->vm_start);
            end = max(end, vma->vm_end);
        }
    }

    MM_READ_UNLOCK(mm)

    mmput(mm);

    if (!matched_dentry) {
        return 0;
    }

    *base_out = base;
    *end_out = end;
    return 1;
}

uintptr_t get_module_base(pid_t pid, char* name, int vm_flag) {
    uintptr_t b = 0, e = 0;

    if (!get_module_bounds(pid, name, vm_flag, &b, &e)) {
        return 0;
    }
    return b;
}

int is_pid_alive(pid_t pid) {
    struct pid* pid_struct;
    struct task_struct* task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    return pid_alive(task);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
pid_t find_process_by_name(const char* name) {
    struct task_struct* task;
    char cmdline[256];
    char* prog_name;
    size_t name_len;
    int ret;

    name_len = strlen(name);
    if (name_len == 0) {
        pr_err("process name is empty\n");
        return -2;
    }

    static int (*my_get_cmdline)(struct task_struct* task, char* buffer, int buflen) = NULL;
    if (my_get_cmdline == NULL) {
        my_get_cmdline = (void*)kallsyms_lookup_name_ex("get_cmdline");
    }

    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        cmdline[0] = '\0';
        if (my_get_cmdline != NULL) {
            ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
        } else {
            ret = -1;
        }

        if (ret < 0) {
            // 回退到task->comm，确保完全匹配
            if (strlen(task->comm) == name_len && strncmp(task->comm, name, name_len) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        } else {
            // 提取程序名（第一个空格之前的部分）
            prog_name = cmdline;
            char* space = strchr(cmdline, ' ');
            if (space) {
                *space = '\0';
            }

            // 提取路径中的文件名部分
            char* slash = strrchr(prog_name, '/');
            if (slash) {
                prog_name = slash + 1;
            }

            if (strlen(prog_name) == name_len && strncmp(prog_name, name, name_len) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}

#else
int get_cmdline_ex(struct task_struct* task, char* buffer, int buflen) {
    int res = 0;
    unsigned int len;
    struct mm_struct* mm = get_task_mm(task);
    unsigned long arg_start, arg_end, env_start, env_end;
    if (!mm)
        goto out;
    if (!mm->arg_end)
        goto out_mm; /* Shh! No looking before we're done */

    spin_lock(&mm->arg_lock);
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    env_start = mm->env_start;
    env_end = mm->env_end;
    spin_unlock(&mm->arg_lock);

    len = arg_end - arg_start;

    if (len > buflen)
        len = buflen;

    res = access_process_vm(task, arg_start, buffer, len, FOLL_FORCE);

    /*
     * If the nul at the end of args has been overwritten, then
     * assume application is using setproctitle(3).
     */
    if (res > 0 && buffer[res - 1] != '\0' && len < buflen) {
        len = strnlen(buffer, res);
        if (len < res) {
            res = len;
        } else {
            len = env_end - env_start;
            if (len > buflen - res)
                len = buflen - res;
            res += access_process_vm(task, env_start, buffer + res, len, FOLL_FORCE);
            res = strnlen(buffer, res);
        }
    }
out_mm:
    mmput(mm);
out:
    return res;
}

pid_t find_process_by_name(const char* name) {
    struct task_struct* task;
    char cmdline[256];
    char* prog_name;
    size_t name_len;
    int ret;

    name_len = strlen(name);
    if (name_len == 0) {
        pr_err("process name is empty\n");
        return -2;
    }

    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        cmdline[0] = '\0';
        ret = get_cmdline_ex(task, cmdline, sizeof(cmdline));

        if (ret < 0) {
            // 回退到task->comm，确保完全匹配
            if (strlen(task->comm) == name_len && strncmp(task->comm, name, name_len) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        } else {
            // 提取程序名（第一个空格之前的部分）
            prog_name = cmdline;
            char* space = strchr(cmdline, ' ');
            if (space) {
                *space = '\0';
            }

            // 提取路径中的文件名部分
            char* slash = strrchr(prog_name, '/');
            if (slash) {
                prog_name = slash + 1;
            }

            if (strlen(prog_name) == name_len && strncmp(prog_name, name, name_len) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}
#endif

void hide_module(void) {
	// 内核模块结构体
	struct module_use *use, *tmp;

	// 摘除链表，/proc/modules 中不可见。
	list_del_init(&THIS_MODULE->list);
	// 摘除kobj，/sys/modules/中不可见。
	kobject_del(&THIS_MODULE->mkobj.kobj);
	// 摘除依赖关系，本例中nf_conntrack的holder中不可见。
	list_for_each_entry_safe(use, tmp, &THIS_MODULE->target_list, target_list)
	{
		list_del(&use->source_list);
		list_del(&use->target_list);
		sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
		kfree(use);
	}
}

__attribute__((no_sanitize("cfi"))) int cfi_bypass(void) {
    int ret = 0;
    unsigned int RET = 0xD65F03C0; // ret指令 (aarch64)
    unsigned int MOV_X0_1 = 0xD2800020; // mov x0, #1 20 00 80 D2

    unsigned long f__cfi_slowpath = kallsyms_lookup_name_ex("__cfi_slowpath");
    if (f__cfi_slowpath) {
        unsigned int* p = (unsigned int*)f__cfi_slowpath;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            paradise_err("patch __cfi_slowpath successed\n");
        } else {
            paradise_info("__cfi_slowpath already patched\n");
        }
    }

    unsigned long f__cfi_slowpath_diag = kallsyms_lookup_name_ex("__cfi_slowpath_diag");
    if (f__cfi_slowpath_diag) {
        unsigned int* p = (unsigned int*)f__cfi_slowpath_diag;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            paradise_err("patch __cfi_slowpath_diag successed\n");
        } else {
            paradise_info("__cfi_slowpath_diag already patched\n");
        }
    }

    unsigned long f_cfi_slowpath = kallsyms_lookup_name_ex("_cfi_slowpath");
    if (f_cfi_slowpath) {
        unsigned int* p = (unsigned int*)f_cfi_slowpath;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            paradise_err("patch _cfi_slowpath successed\n");
        } else {
            paradise_info("_cfi_slowpath already patched\n");
        }
    }

    unsigned long f__cfi_check_fail = kallsyms_lookup_name_ex("__cfi_check_fail");
    if (f__cfi_check_fail) {
        unsigned int* p = (unsigned int*)f__cfi_check_fail;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            paradise_err("patch __cfi_check_fail successed\n");
        } else {
            paradise_info("__cfi_check_fail already patched\n");
        }
    }

    unsigned long f__ubsan_handle_cfi_check_fail_abort = kallsyms_lookup_name_ex("__ubsan_handle_cfi_check_fail_abort");
    if (f__ubsan_handle_cfi_check_fail_abort) {
        unsigned int* p = (unsigned int*)f__ubsan_handle_cfi_check_fail_abort;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            paradise_err("patch __ubsan_handle_cfi_check_fail_abort successed\n");
        } else {
            paradise_info("__ubsan_handle_cfi_check_fail_abort already patched\n");
        }
    }

    unsigned long f__ubsan_handle_cfi_check_fail = kallsyms_lookup_name_ex("__ubsan_handle_cfi_check_fail");
    if (f__ubsan_handle_cfi_check_fail) {
        unsigned int* p = (unsigned int*)f__ubsan_handle_cfi_check_fail;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            paradise_err("patch __ubsan_handle_cfi_check_fail successed\n");
        } else {
            paradise_info("__ubsan_handle_cfi_check_fail already patched\n");
        }
    }

    unsigned long freport_cfi_failure = kallsyms_lookup_name_ex("report_cfi_failure");
    if (freport_cfi_failure) {
        unsigned int* p = (unsigned int*)freport_cfi_failure;
        if(*p != MOV_X0_1) {
            hook_write_range(p, &MOV_X0_1, INSTRUCTION_SIZE);
            hook_write_range(p + 1, &RET, INSTRUCTION_SIZE);
            ret++;
        } else {
            paradise_info("report_cfi_failure already patched\n");
        }
    }

    return ret;
}