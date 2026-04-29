obj-m := paradise.o

paradise-y := \
    src/core/paradise.o \
    src/core/paradise_supercalls.o \
    src/utils/paradise_utils.o \
    src/ioctl/paradise_ioctl.o \
    src/gyro/paradise_gyro.o \
    src/proc/paradise_proc.o \
    src/inlinehook/hijack_arm64.o \
    src/utils/karray_list.o \
    src/utils/cvector.o \
    src/touch/paradise_touch.o \
    src/breakpoint/paradise_hwbp.o \

src := $(if $(filter /%,$(src)),$(src),$(srctree)/$(src))

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- PARADISE_SRC_DIR: $(src))
$(info -- PARADISE_OBJ_DIR: $(obj))

ccflags-y += -I$(src)/src/core -I$(src)/src/net -I$(src)/src/ioctl -I$(src)/src/mm
ccflags-y += -I$(src)/src/inlinehook -I$(src)/src/proc -I$(src)/src/utils -I$(src)/src/gyro
ccflags-y += -I$(src)/src/touch -I$(src)/src/breakpoint

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable

all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean
    
compdb:
	python3 $(MDIR)/.vscode/generate_compdb.py -O $(KDIR) $(MDIR)

.PHONY: all clean
