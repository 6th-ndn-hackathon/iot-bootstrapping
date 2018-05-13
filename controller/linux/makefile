NDNLIB := libndn-cxx
CFLAGS := -std=c++11 `pkg-config --cflags $(NDNLIB)` -I../../device
LIBS   := `pkg-config --libs $(NDNLIB)`
CC     := g++
OBJS   := logger.o controller-sample.o 

controller-sample: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS)

controller-sample.o: controller-sample.cpp
	$(CC) -c $< $(LIBS) $(CFLAGS) -o $@

logger.o: ../../device/logger.cpp
	$(CC) -c $< $(LIBS) $(CFLAGS) -o $@

.PHONY:clean
clean:
	rm controller-sample $(OBJS)
