VISUALIZER_BIN := manifest_visualizor
INC_DIR := ../../core/ ../../projects/linux/
INC := $(addprefix -I,$(sort $(INC_DIR)))

.PHONY: all
all: clean $(VISUALIZER_BIN)

.PHONY: clean
clean:
	rm -rf manifest_visualizor

$(VISUALIZER_BIN): manifest_visualizor.c
	$(CC) $(INC) -g -Wall -Wextra $< -o $@