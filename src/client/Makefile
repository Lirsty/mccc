# ./src/client/Makefile

ROOT_DIR = ../..
INCLUDE_PATH = $(ROOT_DIR)/include

BUILD_DIR := $(ROOT_DIR)/build/client

SRC := $(wildcard *.c)
OBJS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRC))

CFLAGS := -I$(INCLUDE_PATH) -g -Wall -Werror

$(shell mkdir -p $(BUILD_DIR))

all: $(OBJS)

$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)
