#include "paradise_supercalls.h"
#include "paradise_ioctl.h"

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "paradise_utils.h"
#include "karray_list.h"

// Architecture-specific definitions
#if defined(__aarch64__)
#define REBOOT_SYMBOL "__arm64_sys_reboot"
#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_SYSCALL_PARM4(x) ((x)->regs[3])
#define PT_REAL_REGS(regs) ((struct pt_regs *)PT_REGS_PARM1(regs))
#elif defined(__x86_64__)
#define REBOOT_SYMBOL "__x64_sys_reboot"
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_SYSCALL_PARM4(x) ((x)->r10)
#define PT_REAL_REGS(regs) ((struct pt_regs *)PT_REGS_PARM1(regs))
#else
#error "Unsupported architecture"
#endif

// Private data structure is now defined in header file

// Store current file pointer for handlers that need to access private_data
static struct file *current_paradise_file = NULL;

// Function pointer for task_work_add (may not be exported in some kernels)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
typedef int (*task_work_add_t)(struct task_struct *task, struct callback_head *work, bool notify);
#define TWA_RESUME true
#else
typedef int (*task_work_add_t)(struct task_struct *task, struct callback_head *work, enum task_work_notify_mode notify);
#endif
static task_work_add_t task_work_add_ptr = NULL;

// Function pointer for close_fd (VFS internal, needs dynamic lookup)
typedef void (*close_fd_t)(unsigned int fd);
static close_fd_t close_fd_ptr = NULL;

// Function pointer for ksys_close (may not be exported in some kernels)
typedef long (*ksys_close_t)(unsigned int fd);
static ksys_close_t ksys_close_ptr = NULL;

// Function pointer for __close_fd (VFS internal, needs dynamic lookup)
typedef void (*__close_fd_t)(struct files_struct *files, unsigned int fd);
static __close_fd_t __close_fd_ptr = NULL;

/*
 * Direct switch dispatch: O(1) branch tree vs linear scan, no hot-path logging.
 * When adding a PARADISE_IOCTL_* command, add a case here (keep ioctl_handlers[] in sync for init listing).
 */
static long paradise_anon_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    void __user *argp = (void __user *)arg;
    struct file *old_file;
    long ret;

    old_file = current_paradise_file;
    current_paradise_file = filp;

    switch (cmd) {
    case PARADISE_IOCTL_READ_MEMORY:
        ret = do_read_physical_memory(argp);
        break;
    case PARADISE_IOCTL_GET_MODULE_BASE:
        ret = do_get_module_base(argp);
        break;
    case PARADISE_IOCTL_FIND_PROCESS:
        ret = do_find_process(argp);
        break;
    case PARADISE_IOCTL_WRITE_MEMORY:
        ret = do_write_physical_memory(argp);
        break;
    case PARADISE_IOCTL_IS_PROCESS_ALIVE:
        ret = do_is_process_alive(argp);
        break;
    case PARADISE_IOCTL_HIDE_PROCESS:
        ret = do_hide_process(argp);
        break;
    case PARADISE_IOCTL_LIST_PROCESSES:
        ret = do_list_processes(argp);
        break;
    case PARADISE_IOCTL_GYRO_CONFIG:
        ret = do_config_gyro_hook(argp);
        break;
    case PARADISE_IOCTL_HIDE_PATH:
        ret = do_hide_path(argp);
        break;
    case PARADISE_IOCTL_TOUCH_INIT:
        ret = do_touch_init(argp);
        break;
    case PARADISE_IOCTL_TOUCH_EVENT:
        ret = do_touch_event(argp);
        break;
    case PARADISE_IOCTL_TOUCH_DESTROY:
        ret = do_touch_destroy(argp);
        break;
    default:
        current_paradise_file = old_file;
        paradise_debug("paradise ioctl: unsupported command 0x%x\n", cmd);
        return -ENOTTY;
    }

    current_paradise_file = old_file;
    return ret;
}

// File release handler
static int paradise_anon_release(struct inode *inode, struct file *filp)
{
    struct paradise_file_private *priv = filp->private_data;
    
    if (priv) {
        paradise_debug("paradise fd released for pid %d\n", current->pid);

        if (priv->used_pages) {
            for (int i = 0; i < priv->used_pages->size; ++i) {
                struct page* page = (typeof(page))arraylist_get(priv->used_pages, i);
                if (page) {
                    __free_page(page);
                }
            }
            paradise_debug("free %lu used pages\n", priv->used_pages->size);
            arraylist_destroy(priv->used_pages);
        }
        
        kfree(priv);
        filp->private_data = NULL;
    }
    
    return 0;
}

// File open handler - initialize private data
static int paradise_anon_open(struct inode *inode, struct file *filp)
{
    struct paradise_file_private *priv;
    
    priv = kmalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        paradise_err("failed to allocate private data\n");
        return -ENOMEM;
    }
    
    priv->used_pages = arraylist_create(4);
    if (!priv->used_pages) {
        paradise_err("failed to create used_pages arraylist\n");
        kfree(priv);
        return -ENOMEM;
    }
    
    filp->private_data = priv;
    paradise_debug("paradise fd opened for pid %d\n", current->pid);
    
    return 0;
}

// File operations structure
static const struct file_operations paradise_anon_fops = {
    .owner = THIS_MODULE,
    .open = paradise_anon_open,
    .unlocked_ioctl = paradise_anon_ioctl,
    .compat_ioctl = paradise_anon_ioctl,
    .release = paradise_anon_release,
};

// Helper function to get private data from current IOCTL call
struct paradise_file_private* paradise_get_file_private(void)
{
    if (current_paradise_file && current_paradise_file->f_op == &paradise_anon_fops) {
        return (struct paradise_file_private *)current_paradise_file->private_data;
    }
    return NULL;
}

// Install Paradise fd to current process
int paradise_install_fd(void)
{
    struct file *filp;
    int fd;

    // Get unused fd
    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        paradise_err("paradise_install_fd: failed to get unused fd\n");
        return fd;
    }

    // Create anonymous inode file
    filp = anon_inode_getfile(PARADISE_DRIVER_NAME, &paradise_anon_fops, NULL, O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        paradise_err("paradise_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

    // Initialize private data
    if (paradise_anon_open(filp->f_inode, filp)) {
        fput(filp);
        put_unused_fd(fd);
        return -ENOMEM;
    }

    // Install fd
    fd_install(fd, filp);

    paradise_debug("paradise fd installed: %d for pid %d\n", fd, current->pid);

    return fd;
}

// Task work structure for async fd installation
struct paradise_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

// Helper function to close a file descriptor
static void paradise_close_fd(int fd)
{
    if (fd < 0) {
        return;
    }

    // Try close_fd first (kernel >= 5.11)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    if (close_fd_ptr) {
        close_fd_ptr(fd);
        return;
    }
#endif

    // Try ksys_close (dynamic lookup)
    if (ksys_close_ptr) {
        ksys_close_ptr(fd);
        return;
    }

    // Try __close_fd + fput (more complete solution)
    if (__close_fd_ptr && current->files) {
        struct file *filp = fget(fd);
        if (filp) {
            __close_fd_ptr(current->files, fd);
            fput(filp);
            return;
        }
    }

    // Fallback: use fget + fput (fd will remain in table but file will be closed)
    struct file *filp = fget(fd);
    if (filp) {
        fput(filp);
        paradise_warn("fd %d closed but may remain in fd table\n", fd);
    } else {
        paradise_warn("failed to get file pointer for fd %d\n", fd);
    }
}

static void paradise_install_fd_tw_func(struct callback_head *cb)
{
    struct paradise_install_fd_tw *tw = container_of(cb, struct paradise_install_fd_tw, cb);
    int fd = paradise_install_fd();
    
    paradise_debug("paradise_install_fd_tw_func: fd=%d, pid=%d\n", fd, current->pid);

    if (fd >= 0 && tw->outp) {
        if (put_user(fd, tw->outp)) {
            paradise_err("failed to write fd to user space, closing fd %d\n", fd);
            paradise_close_fd(fd);
        } else {
            paradise_debug("paradise fd %d written to user for pid %d\n", fd, current->pid);
        }
    } else if (fd >= 0) {
        paradise_warn("no output pointer provided, closing fd %d\n", fd);
        paradise_close_fd(fd);
    } else {
        paradise_err("failed to install paradise fd for pid %d\n", current->pid);
        if (tw->outp && put_user(-1, tw->outp)) {
            paradise_err("failed to write error code to user space\n");
        }
    }
    
    kfree(tw);
}

// Reboot syscall hook to install fd
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int magic1 = (int)PT_REGS_PARM1(real_regs);
    int magic2 = (int)PT_REGS_PARM2(real_regs);
    unsigned long arg4;

    // Check if this is a request to install Paradise fd
    if (magic1 == PARADISE_INSTALL_MAGIC1 && magic2 == PARADISE_INSTALL_MAGIC2) {
        struct paradise_install_fd_tw *tw;

        paradise_debug("paradise install fd request from pid %d\n", current->pid);

        arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
        if (!arg4) {
            paradise_err("no output pointer provided\n");
            return 0;
        }

        tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
        if (!tw) {
            paradise_err("failed to allocate task work\n");
            return 0;
        }

        tw->outp = (int __user *)arg4;
        tw->cb.func = paradise_install_fd_tw_func;

        if (!task_work_add_ptr) {
            paradise_err("task_work_add not available, cannot install fd\n");
            kfree(tw);
            return 0;
        }

        if (task_work_add_ptr(current, &tw->cb, TWA_RESUME)) {
            kfree(tw);
            paradise_warn("install fd add task_work failed\n");
        } else {
            paradise_debug("task_work added successfully for pid %d\n", current->pid);
        }
    }

    return 0;
}

static struct kprobe reboot_kp = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = reboot_handler_pre,
};

void paradise_supercalls_init(void)
{
    int i;

    paradise_debug("Paradise IOCTL commands registered (see paradise_ioctl.h)\n");
    for (i = 0; ioctl_handlers[i].handler; i++) {
        paradise_debug("  cmd = 0x%08x\n", ioctl_handlers[i].cmd);
    }

    // Initialize task_work_add function pointer
    task_work_add_ptr = (task_work_add_t)kallsyms_lookup_name_ex("task_work_add");
    if (!task_work_add_ptr) {
        paradise_err("task_work_add not found, fd installation via reboot syscall will not work\n");
        // Continue anyway, other functionality may still work
    } else {
        paradise_debug("task_work_add found at %p\n", task_work_add_ptr);
    }

    // Initialize close_fd function pointer (for kernel >= 5.11)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    close_fd_ptr = (close_fd_t)kallsyms_lookup_name_ex("close_fd");
    if (!close_fd_ptr) {
        paradise_warn("close_fd not found, trying ksys_close\n");
    } else {
        paradise_debug("close_fd found at %p\n", close_fd_ptr);
    }
#endif

    // Initialize ksys_close function pointer (fallback)
    ksys_close_ptr = (ksys_close_t)kallsyms_lookup_name_ex("ksys_close");
    if (!ksys_close_ptr) {
        paradise_warn("ksys_close not found, trying __close_fd\n");
    } else {
        paradise_debug("ksys_close found at %p\n", ksys_close_ptr);
    }

    // Initialize __close_fd function pointer (VFS internal)
    __close_fd_ptr = (__close_fd_t)kallsyms_lookup_name_ex("__close_fd");
    if (!__close_fd_ptr) {
        paradise_warn("__close_fd not found, will use fget+fput as fallback\n");
    } else {
        paradise_debug("__close_fd found at %p\n", __close_fd_ptr);
    }

    int rc = register_kprobe(&reboot_kp);
    if (rc) {
        paradise_err("reboot kprobe failed: %d\n", rc);
    } else {
        paradise_debug("reboot kprobe registered successfully\n");
    }
}

void paradise_supercalls_exit(void)
{
    unregister_kprobe(&reboot_kp);
}

