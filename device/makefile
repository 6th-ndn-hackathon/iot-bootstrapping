NDNLIB := libndn-cxx
CFLAGS := -std=c++11 `pkg-config --cflags $(NDNLIB)`
LDFLAGS:= `pkg-config --libs $(NDNLIB)`
CC     := g++
BUILD_DIR ?= ./build
SRC_DIRS := .

SRCS := $(shell find $(SRC_DIRS) -name "*.cpp")
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CPPFLAGS ?= $(INC_FLAGS) -MMD -MP


all: $(BUILD_DIR)/pi.app

test:
	@echo $(SRCS)

$(BUILD_DIR)/pi.app: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# c++ source
$(BUILD_DIR)/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@


.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

-include $(DEPS)

MKDIR_P ?= mkdir -p
