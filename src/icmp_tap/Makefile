CC = g++
CXXFLAGS = -std=c++11 -MMD -fwrapv -ggdb3 -Wall
LDFLAGS += -L/usr/local/lib -lboost_system -lboost_coroutine -lboost_signals -lboost_chrono -lboost_iostreams
ifeq ($(DEBUG),1)
	ALLFLAGS = -fsanitize=address
	CXXFLAGS += $(ALLFLAGS)
	LDFLAGS += $(ALLFLAGS)
endif
OBJECTS := \
	icmp_tap.o \
	tuntap.o \
	inet_checksum.o \
	tap.o \
	icmp_net.o \
	icmp_reply.o \
	icmp_net_frame.o \
	icmp_net_conn.o \
	interruptible_loop.o \
	icmp_net_conn_inbound.o \
	icmp_net_conn_outbound.o \

DEPEND = $(OBJECTS:.o=.d)
EXEC = icmp_tap
$(EXEC): $(OBJECTS)
clean:
	rm -f $(EXEC) $(OBJECTS) $(DEPEND)
-include $(DEPEND)
.PHONY: clean
