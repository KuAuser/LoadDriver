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

    paradise_info("cfi_bypass patched: %d\n", cfi_bypass());

    hide_module();

    return 0;
}

static void __exit paradise_exit(void) {
    paradise_info("bye!\n");
    paradise_touch_exit();
    paradise_gyro_exit();
    paradise_supercalls_exit();
}

module_init(paradise_init);
module_exit(paradise_exit);

MODULE_LICENSE("GPL");

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
