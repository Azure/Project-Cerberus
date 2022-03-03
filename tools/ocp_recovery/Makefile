BUILD := build/
BIN := $(BUILD)ocp_recovery
INC_DIR := ../../core/
INC := $(addprefix -I,$(sort $(INC_DIR)))
SRCS := ocp_recovery.c ../../core/crypto/checksum.c
OBJS := $(addprefix $(BUILD),$(notdir $(SRCS:%.c=%.o)))
CREATEDIR := .create

CFLAGS += $(INC) -g -Wall -Wextra -Werror

.PHONY: all
all: $(BIN)

.PHONY: clean
clean:
	rm -rf $(BUILD)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -pthread -o $@ $(OBJS)

$(BUILD)%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)checksum.o: ../../core/crypto/checksum.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJS): $(BUILD)$(CREATEDIR)

.PRECIOUS: %/$(CREATEDIR)
%/$(CREATEDIR):
	mkdir -p $(@D)
	touch $@
