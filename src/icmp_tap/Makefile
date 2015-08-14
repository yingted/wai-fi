CC = g++
CXXFLAGS = -std=c++11 -Wall
LDFLAGS += -L/usr/local/lib64 -lboost_system -lboost_coroutine
ifeq (DEBUG,1)
	CXXFLAGS += -g3
endif
OBJECTS := icmp_tap.o tuntap.o inet_checksum.o tap.o icmp_net.o
DEPEND := $(OBJECTS:.o=.d)
sinclude $(DEPEND)
EXEC := icmp_tap
$(EXEC): $(OBJECTS)
clean:
	rm -f $(EXEC) $(OBJECTS) $(DEPEND)
.PHONY: clean
