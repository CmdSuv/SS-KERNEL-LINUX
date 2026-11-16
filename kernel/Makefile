# SPDX-License-Identifier: GPL-2.0-only
# Kbuild Makefile for MC SS Sentinel Ephemeral Ring-0 Kernel Module

obj-m += mc_ss_kmod.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ccflags-y += -Wall -Wmissing-prototypes -Wstrict-prototypes

EXTRA_MAKE_FLAGS :=
ifndef LLVM
ifneq ($(wildcard $(KDIR)/.config),)
ifneq ($(shell grep -E '^(CONFIG_CC_IS_CLANG=y|CONFIG_LTO_CLANG_THIN=y|CONFIG_LTO_CLANG_FULL=y)' $(KDIR)/.config 2>/dev/null),)
EXTRA_MAKE_FLAGS += LLVM=1
endif
endif
endif

all:
	$(MAKE) $(EXTRA_MAKE_FLAGS) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) $(EXTRA_MAKE_FLAGS) -C $(KDIR) M=$(PWD) clean
