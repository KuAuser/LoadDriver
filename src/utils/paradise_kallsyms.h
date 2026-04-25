#ifndef PARADISE_KALLSYMS_H
#define PARADISE_KALLSYMS_H

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include "paradise_common.h"
#include "paradise_utils.h"

#define DECLARE_KSYM_RAW(name)                                                                                         \
    static void* _paradise_sym_##name __section(".data");                                                                  \
    static void* __maybe_unused get_##name(void) { return _paradise_sym_##name; }                                          \
    static int __maybe_unused ksym_find_##name(void) {                                                                 \
        _paradise_sym_##name = (void*)kallsyms_lookup_name_ex(#name);                                                         \
        if (!_paradise_sym_##name) {                                                                                       \
            ovo_err("Failed to find symbol: %s\n", #name);                                                             \
            return -ENOENT;                                                                                            \
        }                                                                                                              \
        return 0;                                                                                                      \
    }

#define DECLARE_KSYM_FUN(name, ret, args)                                                                              \
    static ret(*paradise_##name) args = NULL;                                                                              \
    static int __maybe_unused ksym_find_##name(void) {                                                                 \
        if (paradise_##name) {                                                                                             \
            return 0;                                                                                                  \
        }                                                                                                              \
        paradise_##name = (typeof(paradise_##name))kallsyms_lookup_name_ex(#name);                                                \
        if (!paradise_##name) {                                                                                            \
            ovo_err("Failed to find symbol: %s\n", #name);                                                             \
            return -ENOENT;                                                                                            \
        }                                                                                                              \
        return 0;                                                                                                      \
    }

#endif // PARADISE_KALLSYMS_H
