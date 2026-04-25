#ifndef PARADISE_SUPERCALLS_H
#define PARADISE_SUPERCALLS_H

#include "paradise_common.h"

// Magic numbers for reboot hook to install fd
#define PARADISE_INSTALL_MAGIC1 0xB066594D
#define PARADISE_INSTALL_MAGIC2 0xB3664A52

// File descriptor name for anon inode (disguised as common system fd)
#define PARADISE_DRIVER_NAME "[eventpoll]"

// Private data structure stored in file->private_data
struct paradise_file_private {
    struct karray_list* used_pages;
};

// Initialize supercalls (register reboot hook, etc.)
void paradise_supercalls_init(void);
void paradise_supercalls_exit(void);

// Install file descriptor to current process
int paradise_install_fd(void);

// Helper function to get private data from current IOCTL call
struct paradise_file_private* paradise_get_file_private(void);

#endif // PARADISE_SUPERCALLS_H

