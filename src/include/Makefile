CFLAGS += -include waifi_rpc.h -fPIC `pkg-config --cflags python`

all: _waifi_rpc.so waifi_rpc.py
waifi_rpc.py waifi_rpc_wrap.c: waifi_rpc.h
	swig -python $<
_waifi_rpc.so: waifi_rpc_wrap.o
	ld -shared $^ -o $@
clean:
	rm -f waifi_rpc.py waifi_rpc_wrap.c waifi_rpc_wrap.o _waifi_rpc.so *.pyc
.PHONY: all clean
