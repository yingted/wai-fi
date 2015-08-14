CC = g++
CXXFLAGS = -std=c++11
LDFLAGS += -lboost_system
ifeq (DEBUG,1)
	CXXFLAGS += -g3
endif
OBJECTS := icmp_tap.o tuntap.o inet_checksum.o tap.o
icmp_tap: $(OBJECTS)
clean:
	rm $(OBJECTS)
.PHONY: clean
