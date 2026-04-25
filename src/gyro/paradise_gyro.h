#ifndef PARADISE_GYRO_H
#define PARADISE_GYRO_H

#include "paradise_ioctl.h"

int paradise_gyro_init(void);
void paradise_gyro_exit(void);

/* IOCTL handler */
int do_config_gyro_hook(void __user* arg);

#endif /* PARADISE_GYRO_H */

