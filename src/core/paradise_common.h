#ifndef PARADISE_COMMON_H
#define PARADISE_COMMON_H

#include <linux/kernel.h>
#include <linux/module.h>
#include "paradise_utils.h"

#define PARADISE_LOG_PREFIX "[paradise] "
#define paradise_info(fmt, ...) pr_info(PARADISE_LOG_PREFIX fmt, ##__VA_ARGS__)
#define paradise_warn(fmt, ...) pr_warn(PARADISE_LOG_PREFIX fmt, ##__VA_ARGS__)
#define paradise_err(fmt, ...) pr_err(PARADISE_LOG_PREFIX fmt, ##__VA_ARGS__)
#define paradise_debug(fmt, ...) pr_debug(PARADISE_LOG_PREFIX fmt, ##__VA_ARGS__)

#define ovo_info(fmt, ...) pr_info(PARADISE_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_warn(fmt, ...) pr_warn(PARADISE_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_err(fmt, ...) pr_err(PARADISE_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_debug(fmt, ...) pr_debug(PARADISE_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define LUCKY_LUO 0x00000000faceb00c

#define CONFIG_COMPARE_TASK 0
#define CONFIG_COMPARE_PT_REGS 0

/*
 * !!!Poor performance!!!
 */
#define CONFIG_REDIRECT_VIA_ABORT 0

/*
 * !!!!Poor performance!!!
 * The LR address redirection is achieved by using the Linux signal processor mechanism.
 *  > is unsafe and has competition risks.
 *  > is only used for learning and verification that
 *     it can be injected into the executable memory and executed normally without any trace.
 */
#define CONFIG_REDIRECT_VIA_SIGNAL 0

#define CMD_MAX_BYTES (50 * 1024 * 1024)
#define CMD_MAX_PAGES (CMD_MAX_BYTES / PAGE_SIZE)

#endif /* PARADISE_COMMON_H */
