#ifndef PARADISE_TOUCH_H
#define PARADISE_TOUCH_H

#include <linux/types.h>

void paradise_touch_exit(void);

int do_touch_init(void __user *arg);
int do_touch_event(void __user *arg);
int do_touch_destroy(void __user *arg);

#endif /* PARADISE_TOUCH_H */
