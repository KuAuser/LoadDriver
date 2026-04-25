#ifndef ANDROID_PARADISE_PARADISE_PROC_H
#define ANDROID_PARADISE_PARADISE_PROC_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/version.h>
#include "paradise_common.h"
#include <linux/sched.h>

#define PF_INVISIBLE 0x10000000

int is_invisible(pid_t pid);

#endif // ANDROID_PARADISE_PARADISE_PROC_H
