CC = g++
CXXFLAGS = -std=c++11 -MMD -fwrapv
LDFLAGS += -L/usr/local/lib64 -lboost_system -lboost_coroutine -lboost_signals -lboost_chrono
ifeq ($(DEBUG),1)
	CXXFLAGS += -g3 -Wall -fsanitize=address
	LDFLAGS += -g3 -Wall -fsanitize=address
endif
OBJECTS := \
	icmp_tap.o \
	tuntap.o \
	inet_checksum.o \
	tap.o \
	icmp_net.o \
	icmp_reply.o \

DEPEND = $(OBJECTS:.o=.d)
EXEC = icmp_tap
$(EXEC): $(OBJECTS)
clean:
	rm -f $(EXEC) $(OBJECTS) $(DEPEND)
-include $(DEPEND)
.PHONY: clean
