#include "paradise_touch.h"
#include "paradise_common.h"
#include "paradise_ioctl.h"

#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/uaccess.h>

#define TOUCH_MAX_SLOTS 10

struct touch_slot_state {
    int tracking_id;
    int x;
    int y;
    bool active;
};

static struct input_dev *g_touch_dev = NULL;
static struct touch_slot_state g_slots[TOUCH_MAX_SLOTS];
static int g_active_touches = 0;
static int g_next_tracking_id = 1;
static DEFINE_MUTEX(g_touch_lock);
static bool g_touch_initialized = false;

static atomic_t g_exclusive_mode = ATOMIC_INIT(0);
static atomic_t g_injecting = ATOMIC_INIT(0);
static struct kprobe g_input_event_kp;
static bool g_kprobe_installed = false;

/* ---- helpers ---- */

static inline int clampi(int v, int lo, int hi)
{
    if (hi < lo) return v;
    return (v < lo) ? lo : (v > hi) ? hi : v;
}

static inline void get_abs_bounds(struct input_dev *dev, int code,
                                  int *minv, int *maxv)
{
    if (!dev || !test_bit(code, dev->absbit) || !dev->absinfo) {
        *minv = 0; *maxv = 4095;
        return;
    }
    *minv = dev->absinfo[code].minimum;
    *maxv = dev->absinfo[code].maximum;
    if (*maxv <= *minv) { *minv = 0; *maxv = 4095; }
}

static inline bool has_abs(struct input_dev *dev, int code)
{
    return dev && test_bit(code, dev->absbit);
}

static inline bool has_key(struct input_dev *dev, int code)
{
    return dev && test_bit(code, dev->keybit);
}

/*
 * Coordinate mapping: if device max > 1000 and input is in [0,1000],
 * treat as normalised and scale linearly; otherwise clamp.
 */
static inline int map_coord(int v, int minv, int maxv)
{
    if (maxv > 1000 && v >= 0 && v <= 1000) {
        int span = maxv - minv;
        return clampi(minv + (v * span) / 1000, minv, maxv);
    }
    return clampi(v, minv, maxv);
}

static inline bool is_touch_event(unsigned int type, unsigned int code)
{
    if (type == EV_ABS) {
        return code == ABS_MT_SLOT ||
               code == ABS_MT_TRACKING_ID ||
               code == ABS_MT_POSITION_X ||
               code == ABS_MT_POSITION_Y ||
               code == ABS_X ||
               code == ABS_Y;
    }
    if (type == EV_KEY) {
        return code == BTN_TOUCH || code == BTN_TOOL_FINGER;
    }
    return false;
}

/* ---- kprobe: block real touch events in exclusive mode ---- */

static int input_event_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct input_dev *dev;
    unsigned int type, code;

    if (!atomic_read(&g_exclusive_mode))
        return 0;

    if (atomic_read(&g_injecting))
        return 0;

    dev  = (struct input_dev *)regs->regs[0];
    type = (unsigned int)regs->regs[1];
    code = (unsigned int)regs->regs[2];

    if (dev != g_touch_dev)
        return 0;

    if (is_touch_event(type, code)) {
        instruction_pointer_set(regs, regs->regs[30]);
        return 1;
    }

    return 0;
}

/* ---- device discovery ---- */

static struct input_dev *find_touch_device(void)
{
    struct input_dev *dev;
    struct list_head *input_dev_list;
    struct mutex *input_mutex;

    input_dev_list = (struct list_head *)kallsyms_lookup_name_ex("input_dev_list");
    input_mutex    = (struct mutex *)kallsyms_lookup_name_ex("input_mutex");

    if (!input_dev_list || !input_mutex) {
        paradise_err("touch: failed to resolve input_dev_list / input_mutex\n");
        return NULL;
    }

    mutex_lock(input_mutex);
    list_for_each_entry(dev, input_dev_list, node) {
        if (test_bit(EV_ABS, dev->evbit) &&
            test_bit(ABS_MT_POSITION_X, dev->absbit)) {
            paradise_info("touch: found device: %s\n", dev->name);
            mutex_unlock(input_mutex);
            return dev;
        }
    }
    mutex_unlock(input_mutex);

    paradise_err("touch: no touch device found\n");
    return NULL;
}

/* ---- force cleanup: release all active slots ---- */

static void force_cleanup(struct input_dev *dev)
{
    int i;
    bool any_release = false;

    if (!dev) return;

    atomic_inc(&g_injecting);

    for (i = 0; i < TOUCH_MAX_SLOTS; i++) {
        if (g_slots[i].active) {
            input_mt_slot(dev, i);
            input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
            g_slots[i].active = false;
            g_slots[i].tracking_id = -1;
            any_release = true;
        }
    }

    if (any_release) {
        g_active_touches = 0;
        if (has_key(dev, BTN_TOOL_FINGER))
            input_report_key(dev, BTN_TOOL_FINGER, 0);
        if (has_key(dev, BTN_TOUCH))
            input_report_key(dev, BTN_TOUCH, 0);
        input_sync(dev);
    }

    atomic_dec(&g_injecting);
}

/* ---- slot reset ---- */

static void reset_slots(void)
{
    int i;
    for (i = 0; i < TOUCH_MAX_SLOTS; i++) {
        g_slots[i].tracking_id = -1;
        g_slots[i].x = 0;
        g_slots[i].y = 0;
        g_slots[i].active = false;
    }
    g_active_touches = 0;
    g_next_tracking_id = 1;
}

/* ================================================================
 *  IOCTL handlers
 * ================================================================ */

int do_touch_init(void __user *arg)
{
    struct paradise_touch_init_cmd cmd = {};
    struct input_dev *dev;
    int xmin, xmax, ymin, ymax;

    mutex_lock(&g_touch_lock);

    if (g_touch_initialized && g_touch_dev) {
        get_abs_bounds(g_touch_dev, ABS_MT_POSITION_X, &xmin, &xmax);
        get_abs_bounds(g_touch_dev, ABS_MT_POSITION_Y, &ymin, &ymax);
        cmd.max_x = xmax;
        cmd.max_y = ymax;
        mutex_unlock(&g_touch_lock);
        if (copy_to_user(arg, &cmd, sizeof(cmd)))
            return -EFAULT;
        return 0;
    }

    dev = find_touch_device();
    if (!dev) {
        mutex_unlock(&g_touch_lock);
        return -ENODEV;
    }

    g_touch_dev = dev;
    reset_slots();

    /* Install kprobe on input_event for exclusive-mode event blocking */
    if (!g_kprobe_installed) {
        memset(&g_input_event_kp, 0, sizeof(g_input_event_kp));
        g_input_event_kp.symbol_name = "input_event";
        g_input_event_kp.pre_handler = input_event_pre_handler;
        if (register_kprobe(&g_input_event_kp) == 0) {
            g_kprobe_installed = true;
            paradise_info("touch: input_event kprobe installed\n");
        } else {
            paradise_warn("touch: kprobe failed, exclusive mode unavailable\n");
        }
    }

    atomic_set(&g_exclusive_mode, 1);
    g_touch_initialized = true;

    get_abs_bounds(dev, ABS_MT_POSITION_X, &xmin, &xmax);
    get_abs_bounds(dev, ABS_MT_POSITION_Y, &ymin, &ymax);
    cmd.max_x = xmax;
    cmd.max_y = ymax;

    mutex_unlock(&g_touch_lock);

    paradise_info("touch: init dev=%s max_x=%d max_y=%d\n",
                  dev->name, cmd.max_x, cmd.max_y);

    if (copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;

    return 0;
}

int do_touch_event(void __user *arg)
{
    struct paradise_touch_event_cmd cmd;
    struct input_dev *dev;
    struct touch_slot_state *s;
    int xmin, xmax, ymin, ymax;
    int mx, my;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    mutex_lock(&g_touch_lock);

    if (!g_touch_initialized || !g_touch_dev) {
        mutex_unlock(&g_touch_lock);
        return -ENODEV;
    }

    dev = g_touch_dev;

    if (cmd.slot < 0 || cmd.slot >= TOUCH_MAX_SLOTS) {
        mutex_unlock(&g_touch_lock);
        return -EINVAL;
    }

    s = &g_slots[cmd.slot];
    get_abs_bounds(dev, ABS_MT_POSITION_X, &xmin, &xmax);
    get_abs_bounds(dev, ABS_MT_POSITION_Y, &ymin, &ymax);

    atomic_inc(&g_injecting);

    switch (cmd.action) {
    case PARADISE_TOUCH_DOWN:
        if (!s->active) {
            s->active = true;
            if (g_next_tracking_id == -1) g_next_tracking_id = 1;
            s->tracking_id = g_next_tracking_id++;
            if (g_next_tracking_id <= 0) g_next_tracking_id = 1;
            g_active_touches++;
        }
        mx = map_coord(cmd.x, xmin, xmax);
        my = map_coord(cmd.y, ymin, ymax);
        s->x = mx; s->y = my;

        input_mt_slot(dev, cmd.slot);
        input_report_abs(dev, ABS_MT_TRACKING_ID, s->tracking_id);
        input_report_abs(dev, ABS_MT_POSITION_X, s->x);
        input_report_abs(dev, ABS_MT_POSITION_Y, s->y);
        if (has_abs(dev, ABS_X)) input_report_abs(dev, ABS_X, s->x);
        if (has_abs(dev, ABS_Y)) input_report_abs(dev, ABS_Y, s->y);
        if (g_active_touches == 1) {
            if (has_key(dev, BTN_TOUCH))
                input_report_key(dev, BTN_TOUCH, 1);
            if (has_key(dev, BTN_TOOL_FINGER))
                input_report_key(dev, BTN_TOOL_FINGER, 1);
        }
        input_sync(dev);
        break;

    case PARADISE_TOUCH_MOVE:
        if (!s->active) {
            /* auto-promote to DOWN */
            s->active = true;
            if (g_next_tracking_id == -1) g_next_tracking_id = 1;
            s->tracking_id = g_next_tracking_id++;
            if (g_next_tracking_id <= 0) g_next_tracking_id = 1;
            g_active_touches++;

            mx = map_coord(cmd.x, xmin, xmax);
            my = map_coord(cmd.y, ymin, ymax);
            s->x = mx; s->y = my;

            input_mt_slot(dev, cmd.slot);
            input_report_abs(dev, ABS_MT_TRACKING_ID, s->tracking_id);
            input_report_abs(dev, ABS_MT_POSITION_X, s->x);
            input_report_abs(dev, ABS_MT_POSITION_Y, s->y);
            if (has_abs(dev, ABS_X)) input_report_abs(dev, ABS_X, s->x);
            if (has_abs(dev, ABS_Y)) input_report_abs(dev, ABS_Y, s->y);
            if (g_active_touches == 1) {
                if (has_key(dev, BTN_TOUCH))
                    input_report_key(dev, BTN_TOUCH, 1);
                if (has_key(dev, BTN_TOOL_FINGER))
                    input_report_key(dev, BTN_TOOL_FINGER, 1);
            }
            input_sync(dev);
        } else {
            mx = map_coord(cmd.x, xmin, xmax);
            my = map_coord(cmd.y, ymin, ymax);
            s->x = mx; s->y = my;

            input_mt_slot(dev, cmd.slot);
            input_report_abs(dev, ABS_MT_POSITION_X, s->x);
            input_report_abs(dev, ABS_MT_POSITION_Y, s->y);
            if (has_abs(dev, ABS_X)) input_report_abs(dev, ABS_X, s->x);
            if (has_abs(dev, ABS_Y)) input_report_abs(dev, ABS_Y, s->y);
            input_sync(dev);
        }
        break;

    case PARADISE_TOUCH_UP:
        if (s->active) {
            input_mt_slot(dev, cmd.slot);
            input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
            s->active = false;
            s->tracking_id = -1;
            if (g_active_touches > 0) g_active_touches--;
            if (g_active_touches == 0) {
                if (has_key(dev, BTN_TOOL_FINGER))
                    input_report_key(dev, BTN_TOOL_FINGER, 0);
                if (has_key(dev, BTN_TOUCH))
                    input_report_key(dev, BTN_TOUCH, 0);
            }
            input_sync(dev);
        }
        break;

    default:
        atomic_dec(&g_injecting);
        mutex_unlock(&g_touch_lock);
        return -EINVAL;
    }

    atomic_dec(&g_injecting);
    mutex_unlock(&g_touch_lock);
    return 0;
}

int do_touch_destroy(void __user *arg)
{
    mutex_lock(&g_touch_lock);

    if (!g_touch_initialized) {
        mutex_unlock(&g_touch_lock);
        return 0;
    }

    atomic_set(&g_exclusive_mode, 0);

    if (g_touch_dev)
        force_cleanup(g_touch_dev);

    if (g_kprobe_installed) {
        unregister_kprobe(&g_input_event_kp);
        g_kprobe_installed = false;
        paradise_info("touch: kprobe removed\n");
    }

    g_touch_dev = NULL;
    g_touch_initialized = false;

    mutex_unlock(&g_touch_lock);

    paradise_info("touch: destroyed\n");
    return 0;
}

/* ---- module lifecycle ---- */

void paradise_touch_exit(void)
{
    do_touch_destroy(NULL);
}
