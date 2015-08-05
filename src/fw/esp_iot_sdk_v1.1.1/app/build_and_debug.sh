#!/bin/bash
set -e
GDB_STUB_STARTUP=1 bash gen_misc.sh </dev/null
esptool.py -b 921600 write_flash -ff 80m 0x00000 ../bin/eagle.flash.bin 0x40000 ../bin/eagle.irom0text.bin
stty -F /dev/ttyUSB0 115200
sleep 1
exec xtensa-lx106-elf-gdb -x gdb_init_startup
