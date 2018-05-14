NDNLIB := libndn-cxx
CFLAGS := -std=c++11 `pkg-config --cflags $(NDNLIB)`
LDFLAGS:= `pkg-config --libs $(NDNLIB)`
CC     := g++
BUILD_DIR ?= ./build
SRC_DIRS := .

PI_SRCS := $(shell find $(SRC_DIRS) -name "*.cpp" -not -path "./arduino/*")
AR_SRCS := $(shell find $(SRC_DIRS) -name "*.cpp" -not -path "./pi/*")
PI_OBJS := $(PI_SRCS:%=$(BUILD_DIR)/%.o)
AR_OBJS := $(AR_SRCS:%=$(BUILD_DIR)/%.o)
PI_DEPS := $(PI_OBJS:.o=.d)
AR_DEPS := $(AR_OBJS:.o=.d)

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CPPFLAGS ?= $(INC_FLAGS) -MMD -MP


all: $(BUILD_DIR)/bootstrap.app $(BUILD_DIR)/led.app

test:
	@echo $(PI_SRCS)

$(BUILD_DIR)/bootstrap.app: $(PI_OBJS)
	$(CC) $(PI_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/led.app: $(AR_OBJS)
	$(CC) $(AR_OBJS) -o $@ $(LDFLAGS)

# c++ source
$(BUILD_DIR)/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@


.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

-include $(PI_DEPS)
-include $(AR_DEPS)

MKDIR_P ?= mkdir -p
