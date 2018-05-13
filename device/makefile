NDNLIB := libndn-cxx
CFLAGS := -std=c++11 `pkg-config --cflags $(NDNLIB)`
LDFLAGS:= `pkg-config --libs $(NDNLIB)`
CC     := g++
BUILD_DIR ?= ./build
SRC_DIRS := .

PI_SRCS := $(shell find $(SRC_DIRS) -name "*.cpp" -not -path "./arduino/*")
PI_OBJS := $(PI_SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CPPFLAGS ?= $(INC_FLAGS) -MMD -MP


all: $(BUILD_DIR)/pi.app

test:
	@echo $(PI_SRCS)

$(BUILD_DIR)/pi.app: $(PI_OBJS)
	$(CC) $(PI_OBJS) -o $@ $(LDFLAGS)

# c++ source
$(BUILD_DIR)/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@


.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

-include $(DEPS)

MKDIR_P ?= mkdir -p
