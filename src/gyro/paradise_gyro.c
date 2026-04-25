#include "paradise_gyro.h"

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "paradise_common.h"
#include "paradise_utils.h"

#define PARADISE_GYRO_MAX_COPY (2 * 1024 * 1024UL)
#define ASENSOR_TYPE_GYROSCOPE 4
#define ASENSOR_TYPE_GYROSCOPE_UNCAL 16

#define SENDTO_SYMBOL "__arm64_sys_sendto"

struct ASensorEvent_kernel {
    int32_t version;
    int32_t sensor;
    int32_t type;
    int32_t reserved0;
    int64_t timestamp;
    union {
        uint32_t data[16]; /* float -> uint32_t */
    };
    uint32_t flags;
    int32_t reserved1[3];
};

struct paradise_gyro_state {
    bool enabled;
    uint32_t type_mask;
    uint32_t axis_raw[3]; /* x, y, z IEEE754 bits */
};

static struct paradise_gyro_state gyro_state = {
    .enabled = false,
    .type_mask = PARADISE_GYRO_MASK_ALL,
    .axis_raw = {0, 0, 0},
};

static DEFINE_MUTEX(gyro_ctrl_lock);

static inline uint32_t float_add(uint32_t a, uint32_t b)
{
    int32_t exp_a, exp_b, exp_result;
    uint32_t mant_a, mant_b;
    uint32_t sign_a, sign_b;
    int64_t mant_result;
    
    if ((a & 0x7FFFFFFF) == 0) return b;
    if ((b & 0x7FFFFFFF) == 0) return a;
    
    sign_a = a >> 31;
    exp_a = ((a >> 23) & 0xFF);
    mant_a = (a & 0x7FFFFF) | 0x800000;
    
    sign_b = b >> 31;
    exp_b = ((b >> 23) & 0xFF);
    mant_b = (b & 0x7FFFFF) | 0x800000;
    
    if (exp_a > exp_b) {
        if (exp_a - exp_b > 24) return a;
        mant_b >>= (exp_a - exp_b);
        exp_result = exp_a;
    } else if (exp_b > exp_a) {
        if (exp_b - exp_a > 24) return b;
        mant_a >>= (exp_b - exp_a);
        exp_result = exp_b;
    } else {
        exp_result = exp_a;
    }
    
    if (sign_a == sign_b) {
        mant_result = (int64_t)mant_a + (int64_t)mant_b;
        if (mant_result & 0x1000000) {
            mant_result >>= 1;
            exp_result++;
        }
    } else {
        if (mant_a >= mant_b) {
            mant_result = (int64_t)mant_a - (int64_t)mant_b;
        } else {
            mant_result = (int64_t)mant_b - (int64_t)mant_a;
            sign_a = sign_b;
        }
        
        if (mant_result == 0) return 0;
        
        while (mant_result && !(mant_result & 0x800000)) {
            mant_result <<= 1;
            exp_result--;
        }
    }
    
    if (exp_result >= 255) return (sign_a << 31) | 0x7F800000;
    if (exp_result <= 0) return (sign_a << 31);
    
    return (sign_a << 31) | ((exp_result & 0xFF) << 23) | ((uint32_t)mant_result & 0x7FFFFF);
}

/*
 * sendto(int fd, void __user *buff, size_t len, unsigned flags,
 *        struct sockaddr __user *addr, int addr_len)
 *
 * On arm64, __arm64_sys_sendto receives a wrapper pt_regs whose first
 * register points to the real user pt_regs.  The real regs carry:
 *   regs[0] = fd
 *   regs[1] = buff
 *   regs[2] = len
 */
static int gyro_sendto_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = (struct pt_regs *)regs->regs[0];
    void __user *user_buf;
    size_t len;
    size_t event_size = sizeof(struct ASensorEvent_kernel);
    size_t count;
    struct ASensorEvent_kernel *kernel_buffer = NULL;
    struct paradise_gyro_state state;
    bool patched = false;
    unsigned long res;
    int i;

    if (!READ_ONCE(gyro_state.enabled))
        return 0;

    user_buf = (void __user *)real_regs->regs[1];
    len = (size_t)real_regs->regs[2];

    if (!user_buf || len == 0)
        return 0;

    if (len % event_size != 0)
        return 0;

    if (len > PARADISE_GYRO_MAX_COPY)
        return 0;

    count = len / event_size;

    state.type_mask = READ_ONCE(gyro_state.type_mask);
    state.axis_raw[0] = READ_ONCE(gyro_state.axis_raw[0]);
    state.axis_raw[1] = READ_ONCE(gyro_state.axis_raw[1]);

    kernel_buffer = vmalloc(len);
    if (!kernel_buffer)
        return 0;

    if (copy_from_user(kernel_buffer, user_buf, len) != 0) {
        vfree(kernel_buffer);
        return 0;
    }

    for (i = 0; i < count; i++) {
        int type = kernel_buffer[i].type;
        bool match_gyro = (type == ASENSOR_TYPE_GYROSCOPE) && (state.type_mask & PARADISE_GYRO_MASK_GYRO);
        bool match_uncal = (type == ASENSOR_TYPE_GYROSCOPE_UNCAL) && (state.type_mask & PARADISE_GYRO_MASK_UNCAL);

        if (!match_gyro && !match_uncal)
            continue;

        kernel_buffer[i].data[0] = float_add(kernel_buffer[i].data[0], state.axis_raw[0]);
        kernel_buffer[i].data[1] = float_add(kernel_buffer[i].data[1], state.axis_raw[1]);
        patched = true;
    }

    if (patched) {
        res = copy_to_user(user_buf, kernel_buffer, len);
        if (res != 0)
            paradise_warn("gyro: failed to copy back (%lu bytes missing)\n", res);
    }

    vfree(kernel_buffer);
    return 0;
}

static struct kprobe sendto_kp = {
    .symbol_name = SENDTO_SYMBOL,
    .pre_handler = gyro_sendto_handler,
};

int do_config_gyro_hook(void __user* arg)
{
    struct paradise_gyro_config_cmd cmd;
    uint32_t x_raw = 0, y_raw = 0;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    if (cmd.type_mask == 0)
        cmd.type_mask = PARADISE_GYRO_MASK_ALL;

    memcpy(&x_raw, &cmd.x, sizeof(uint32_t));
    memcpy(&y_raw, &cmd.y, sizeof(uint32_t));

    mutex_lock(&gyro_ctrl_lock);

    gyro_state.axis_raw[0] = x_raw;
    gyro_state.axis_raw[1] = y_raw;
    gyro_state.type_mask = cmd.type_mask;
    gyro_state.enabled = !!cmd.enable;

    mutex_unlock(&gyro_ctrl_lock);

    cmd.enable = gyro_state.enabled ? 1 : 0;
    cmd.type_mask = gyro_state.type_mask;
    memcpy(&cmd.x, &gyro_state.axis_raw[0], sizeof(uint32_t));
    memcpy(&cmd.y, &gyro_state.axis_raw[1], sizeof(uint32_t));

    if (copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;

    return 0;
}

int paradise_gyro_init(void)
{
    int ret;

    ret = register_kprobe(&sendto_kp);
    if (ret) {
        paradise_err("gyro: register kprobe on %s failed (%d)\n", SENDTO_SYMBOL, ret);
        return ret;
    }

    paradise_info("gyro: kprobe on %s registered\n", SENDTO_SYMBOL);
    return 0;
}

void paradise_gyro_exit(void)
{
    unregister_kprobe(&sendto_kp);
    gyro_state.enabled = false;
    paradise_info("gyro: kprobe unregistered\n");
}
