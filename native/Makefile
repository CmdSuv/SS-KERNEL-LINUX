# SPDX-License-Identifier: GPL-2.0-only
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror=implicit-function-declaration

TARGET := ss_kernel_probe

all: $(TARGET)

$(TARGET): ss_kernel_probe.c
	$(CC) $(CFLAGS) -o $(TARGET) ss_kernel_probe.c

clean:
	rm -f $(TARGET)
