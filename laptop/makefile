NDNLIB := libndn-cxx
CFLAGS := -std=c++11 `pkg-config --cflags $(NDNLIB)` -I../device
LIBS   := `pkg-config --libs $(NDNLIB)`
CC     := g++
OBJS   := logger.o led_consumer.o 

led_consumer: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS)

led_consumer.o: led_consumer.cpp
	$(CC) -c $< $(LIBS) $(CFLAGS) -o $@

logger.o: ../device/logger.cpp
	$(CC) -c $< $(LIBS) $(CFLAGS) -o $@

.PHONY:clean
clean:
	rm led_consumer $(OBJS)
