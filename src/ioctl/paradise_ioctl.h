#ifndef PARADISE_IOCTL_H
#define PARADISE_IOCTL_H

#include "paradise_common.h"
#include "paradise_touch.h"
#include <asm/ptrace.h>

struct paradise_memory_rw_cmd {
    pid_t pid; /* Input: Process ID owning the virtual address */
    uintptr_t src_va; /* Input: Virtual address to read from (for read) or write to (for write) */
    uintptr_t dst_va; /* Input: Virtual address to read from (for read) or write to (for write) */
    size_t size; /* Input: Size of memory to read/write */
    uintptr_t phy_addr; /* Output: Physical address of the source virtual address */
};

struct paradise_get_module_base_cmd {
    pid_t pid; /* Input: Process ID */
    char name[256]; /* Input: Module name */
    uintptr_t base; /* Output: Lowest vm_start among matching VMAs */
    uintptr_t end; /* Output: Highest vm_end (exclusive), covering all segments of the same mapping */
    int vm_flag; /* Input: VM flag to filter (e.g., VM_EXEC) */
};

struct paradise_find_proc_cmd {
    pid_t pid; /* Output: Process ID */
    char name[256]; /* Input: Process name */
};

struct paradise_is_proc_alive_cmd {
    pid_t pid; /* Output: Process ID */
    int alive; /* Output: 1 if alive, 0 if not */
};

struct paradise_hide_proc_cmd {
    pid_t pid; /* Input: Process ID */
    int hide; /* Input: 1 to hide, 0 to unhide */
};

#define PARADISE_HIDE_PATH_MAX 512

struct paradise_hide_path_cmd {
    char path[PARADISE_HIDE_PATH_MAX]; /* Input: absolute path to hide (tmpfs overlay), NUL-terminated */
    int hide; /* Input: 1 to hide, 0 to unhide */
};

struct paradise_list_processes_cmd {
    u8* __user bitmap; /* Input: User-space bitmap buffer (at least 8192 bytes for PID 0-65535) */
    size_t bitmap_size; /* Input: Size of bitmap in bytes (must be at least 8192) */
    size_t process_count; /* Output: Total number of processes (number of set bits) */
};

/* Gyro override types (matches ASENSOR_TYPE_GYROSCOPE/UNCALIBRATED) */
#define PARADISE_GYRO_MASK_GYRO (1u << 0)
#define PARADISE_GYRO_MASK_UNCAL (1u << 1)
#define PARADISE_GYRO_MASK_ALL (PARADISE_GYRO_MASK_GYRO | PARADISE_GYRO_MASK_UNCAL)

struct paradise_gyro_config_cmd {
    int enable; /* Input: 1 enable hook, 0 disable */
    uint32_t type_mask; /* Input/Output: bit0 gyro, bit1 uncal */
    float x; /* Input/Output: X axis value */
    float y; /* Input/Output: Y axis value */
};

/* Touch action constants */
#define PARADISE_TOUCH_DOWN  0
#define PARADISE_TOUCH_MOVE  1
#define PARADISE_TOUCH_UP    2

struct paradise_touch_init_cmd {
    int max_x; /* Output: maximum X coordinate of the touch device */
    int max_y; /* Output: maximum Y coordinate of the touch device */
};

struct paradise_touch_event_cmd {
    int action; /* Input: PARADISE_TOUCH_DOWN / MOVE / UP */
    int slot;   /* Input: MT slot index (0-9) */
    int x;      /* Input: X coordinate */
    int y;      /* Input: Y coordinate */
};

/* IOCTL command for reading physical memory */
#define PARADISE_IOCTL_READ_MEMORY _IOWR('W', 9, struct paradise_memory_rw_cmd)
/* IOCTL command for getting module base address */
#define PARADISE_IOCTL_GET_MODULE_BASE _IOWR('W', 10, struct paradise_get_module_base_cmd)
/* IOCTL command for finding a process by name */
#define PARADISE_IOCTL_FIND_PROCESS _IOWR('W', 11, struct paradise_find_proc_cmd)
/* IOCTL command for writing physical memory */
#define PARADISE_IOCTL_WRITE_MEMORY _IOWR('W', 12, struct paradise_memory_rw_cmd)
/* IOCTL command for checking if a process is alive */
#define PARADISE_IOCTL_IS_PROCESS_ALIVE _IOWR('W', 13, struct paradise_is_proc_alive_cmd)
/* IOCTL command for hiding/unhiding a process */
#define PARADISE_IOCTL_HIDE_PROCESS _IOWR('W', 14, struct paradise_hide_proc_cmd)
/* IOCTL command for listing all processes as a bitmap */
#define PARADISE_IOCTL_LIST_PROCESSES _IOWR('W', 19, struct paradise_list_processes_cmd)
/* IOCTL command for configuring gyroscope hook */
#define PARADISE_IOCTL_GYRO_CONFIG _IOWR('W', 21, struct paradise_gyro_config_cmd)
/* IOCTL command for hiding/unhiding an arbitrary vfs path (tmpfs overlay, same mechanism as hide process paths) */
#define PARADISE_IOCTL_HIDE_PATH _IOWR('W', 22, struct paradise_hide_path_cmd)
/* IOCTL commands for touch injection */
#define PARADISE_IOCTL_TOUCH_INIT     _IOR('W', 30, struct paradise_touch_init_cmd)
#define PARADISE_IOCTL_TOUCH_EVENT    _IOW('W', 31, struct paradise_touch_event_cmd)
#define PARADISE_IOCTL_TOUCH_DESTROY  _IO('W', 32)

int do_read_physical_memory(void __user* arg);
int do_get_module_base(void __user* arg);
int do_find_process(void __user* arg);
int do_write_physical_memory(void __user* arg);
int do_is_process_alive(void __user* arg);
int do_hide_process(void __user* arg);
int do_hide_path(void __user* arg);
int do_list_processes(void __user* arg);
int do_config_gyro_hook(void __user* arg);
/* touch handlers are declared in paradise_touch.h */

typedef int (*ioctl_handler_t)(void __user* arg);

static const struct ioctl_cmd_map {
    unsigned int cmd;
    ioctl_handler_t handler;
} ioctl_handlers[] = {
    {.cmd = PARADISE_IOCTL_READ_MEMORY, .handler = do_read_physical_memory},
    {.cmd = PARADISE_IOCTL_GET_MODULE_BASE, .handler = do_get_module_base},
    {.cmd = PARADISE_IOCTL_FIND_PROCESS, .handler = do_find_process},
    {.cmd = PARADISE_IOCTL_WRITE_MEMORY, .handler = do_write_physical_memory},
    {.cmd = PARADISE_IOCTL_IS_PROCESS_ALIVE, .handler = do_is_process_alive},
    {.cmd = PARADISE_IOCTL_HIDE_PROCESS, .handler = do_hide_process},
    {.cmd = PARADISE_IOCTL_LIST_PROCESSES, .handler = do_list_processes},
    {.cmd = PARADISE_IOCTL_GYRO_CONFIG, .handler = do_config_gyro_hook},
    {.cmd = PARADISE_IOCTL_HIDE_PATH, .handler = do_hide_path},
    {.cmd = PARADISE_IOCTL_TOUCH_INIT, .handler = do_touch_init},
    {.cmd = PARADISE_IOCTL_TOUCH_EVENT, .handler = do_touch_event},
    {.cmd = PARADISE_IOCTL_TOUCH_DESTROY, .handler = do_touch_destroy},
    {.cmd = 0, .handler = NULL} /* Sentinel to mark end of array */
};

#endif // PARADISE_IOCTL_H