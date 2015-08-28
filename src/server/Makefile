INCLUDEDIR := ../include
INCLUDES := -I$(INCLUDEDIR)
CFLAGS += $(INCLUDES) -fPIC `pkg-config --cflags python`

all: _waifi_rpc.so waifi_rpc.py
waifi_rpc.py waifi_rpc_wrap.c: waifi_rpc.i $(INCLUDEDIR)/waifi_rpc.h
	swig -python $< $(INCLUDES)
_waifi_rpc.so: waifi_rpc_wrap.o
	ld -shared $^ -o $@
clean:
	rm -f waifi_rpc.py waifi_rpc_wrap.c waifi_rpc_wrap.o _waifi_rpc.so *.pyc
test: all
	cd .. && python -m doctest server/[a-zA-Z]*.py
.PHONY: all clean test
