#include <asm/tlbflush.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include "paradise_common.h"
#include "paradise_kallsyms.h"
#include "paradise_supercalls.h"
#include "paradise_utils.h"
#include "paradise_ioctl.h"
#include "hijack_arm64.h"
#include "paradise_gyro.h"
#include "paradise_touch.h"
#include "paradise_hwbp.h"

static int __init paradise_init(void) {
    int ret;
    paradise_info("hello world\n");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    ret = disable_kprobe_blacklist();
    if (ret) {
        paradise_err("disable_kprobe_blacklist failed: %d\n", ret);
        return ret;
    }
#endif

    ret = init_arch();
    if (ret) {
        paradise_err("init_arch failed: %d\n", ret);
        return ret;
    }

    // Initialize supercalls (anonymous inode communication)
    paradise_supercalls_init();

    ret = paradise_gyro_init();
    if (ret) {
        paradise_err("paradise_gyro_init failed: %d\n", ret);
        paradise_supercalls_exit();
        return ret;
    }

    /* hw_breakpoint 子系统: 失败不致命, 模块整体仍可用 (内存读/隐藏进程都还在). */
    ret = paradise_hwbp_init();
    if (ret) {
        paradise_warn("paradise_hwbp_init failed: %d (hw breakpoints disabled)\n", ret);
        /* fall through, 不退出 */
    }

    paradise_info("cfi_bypass patched: %d\n", cfi_bypass());

    hide_module();

    return 0;
}

static void __exit paradise_exit(void) {
    paradise_info("bye!\n");
    /* 先卸 hwbp: unregister_wide_hw_breakpoint 内部要 perf_event_release_kernel,
     * 在 supercalls_exit 把 fd 回收掉之前清理掉 BP 链表. */
    paradise_hwbp_exit();
    paradise_touch_exit();
    paradise_gyro_exit();
    paradise_supercalls_exit();
}

module_init(paradise_init);
module_exit(paradise_exit);

MODULE_LICENSE("GPL");

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
