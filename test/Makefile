# ./test/Makefile
ROOT_DIR = ..

LIBS = -lssl -lcrypto -lz
INCLUDE_FLAG = -I/usr/local/include -I$(ROOT_DIR)/include 
LDFLAGS = -L/usr/local/lib $(LIBS)
BUILD_DIR := $(ROOT_DIR)/build
$(shell mkdir -p $(BUILD_DIR))

CFLAGS := $(INCLUDE_FLAG) -g -Wall -Werror

SRC := $(wildcard *.c)
CLIENT_SRC := $(wildcard $(ROOT_DIR)/src/client/*.c)
NETWORK_SRC := $(wildcard $(ROOT_DIR)/src/network/*.c)

OBJ := $(SRC:%.c=$(BUILD_DIR)/test/%.o)
CLIENT_OBJ := $(addprefix $(BUILD_DIR)/client/, $(notdir $(CLIENT_SRC:.c=.o)))
NETWORK_OBJ := $(addprefix $(BUILD_DIR)/network/, $(notdir $(NETWORK_SRC:.c=.o)))
TARGET := t

$(shell mkdir -p $(BUILD_DIR)/test)

all : $(TARGET)

$(TARGET) : $(OBJ) $(NETWORK_OBJ) $(CLIENT_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ 

$(OBJ) : $(SRC) 
	$(CC) $(CFLAGS) -c $< -o $@ 

$(CLIENT_OBJ) :
	cd $(ROOT_DIR)/src/client && $(MAKE)

$(NETWORK_OBJ) :
	cd $(ROOT_DIR)/src/network && $(MAKE)

clean:
	rm -f $(OBJ)
