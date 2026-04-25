#ifndef PARADISE_UTILS_H
#define PARADISE_UTILS_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/version.h>
#include "paradise_common.h"
#include "karray_list.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
#include <linux/mmap_lock.h>
#define MM_READ_LOCK(mm) mmap_read_lock(mm);
#define MM_READ_UNLOCK(mm) mmap_read_unlock(mm);
#define MM_WRITE_LOCK(mm) mmap_write_lock(mm);
#define MM_WRITE_UNLOCK(mm) mmap_write_unlock(mm);
#else
#include <linux/rwsem.h>
#define MM_READ_LOCK(mm) down_read(&(mm)->mmap_sem);
#define MM_READ_UNLOCK(mm) up_read(&(mm)->mmap_sem);
#define MM_WRITE_LOCK(mm) down_write(&(mm)->mmap_sem);
#define MM_WRITE_UNLOCK(mm) up_write(&(mm)->mmap_sem);
#endif

bool is_file_exist(const char* filename);

unsigned long kallsyms_lookup_name_ex(const char* symbol_name);

struct task_struct* get_target_task(pid_t pid);

int disable_kprobe_blacklist(void);

void compare_pt_regs(struct pt_regs* regs1, struct pt_regs* regs2);
void compare_task_struct(struct task_struct* task1, struct task_struct* task2);

static __always_inline void set_current(struct task_struct* tsk) {
    unsigned long tmp = (unsigned long)tsk;

    asm volatile("msr sp_el0, %0" : : "r"(tmp) : "memory");
}

uintptr_t get_module_base(pid_t pid, char* name, int vm_flag);

/* 同一映射文件（按 dentry 关联）的所有匹配 VMA：最低 vm_start、最高 vm_end；成功返回 1，失败返回 0 */
int get_module_bounds(pid_t pid, char* name, int vm_flag, uintptr_t* base_out, uintptr_t* end_out);

int is_pid_alive(pid_t pid);

pid_t find_process_by_name(const char* name);

void hide_module(void);

bool bypass_cfi(void);

#endif // PARADISE_UTILS_H
