# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

BUILD := build/
BIN := $(BUILD)ocp_recovery
BIN_AARDVARK := $(BUILD)ocp_recovery_aardvark
INC_DIR := ../../core/ ./aardvark
INC := $(addprefix -I,$(sort $(INC_DIR)))
SRCS := ocp_recovery.c  i2c_ioctl.c checksum.c 
SRCS_AARDVARK := ocp_recovery.c i2c_aardvark.c aardvark.c checksum.c
OBJS := $(addprefix $(BUILD),$(notdir $(SRCS:%.c=%.o)))
OBJS_AARDVARK := $(addprefix $(BUILD),$(notdir $(SRCS_AARDVARK:%.c=%.o)))
CREATEDIR := .create
CFLAGS += $(INC) -g -Wall -Wextra -Werror

.PHONY: all
all: $(BIN)

aardvark: $(OBJS_AARDVARK)
	$(CC) $(CFLAGS) $(LDFLAGS) -pthread -o  $(BIN_AARDVARK) $(OBJS_AARDVARK)

.PHONY: clean
clean:
	rm -rf $(BUILD)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -pthread -o $@ $(OBJS)

$(BUILD)%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)aardvark.o: ./aardvark/aardvark.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)checksum.o: ../../core/crypto/checksum.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJS): $(BUILD)$(CREATEDIR)

.PRECIOUS: %/$(CREATEDIR)
%/$(CREATEDIR):
	mkdir -p $(@D)
	touch $@
	if [ -r ./aardvark/aardvark.so ];  then cp -f aardvark/aardvark.so $(BUILD); fi;
