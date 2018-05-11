NDNLIB := libndn-cxx
CFLAGS := -std=c++11 `pkg-config --cflags $(NDNLIB)`
LIBS   := `pkg-config --libs $(NDNLIB)`
CC     := g++
TARGET := controller-sample

all: $(TARGET)

%: %.cpp
	$(CC) $< $(LIBS) $(CFLAGS) -o $@

.PHONY:clean
clean:
	rm $(TARGET)
