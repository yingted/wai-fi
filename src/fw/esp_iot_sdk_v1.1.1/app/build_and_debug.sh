#!/bin/bash
set -e
GDB_STUB_STARTUP=1 ./build.sh
esptool.py -b 921600 write_flash -ff 80m 0x00000 ../bin/upgrade/boot.bin 0x01000 ../bin/upgrade/user1.2048.new.5.bin
#esptool.py -b 921600 write_flash -ff 80m 0x00000 ../bin/upgrade/boot.bin 0x41000 ../bin/upgrade/user2.2048.new.5.bin
stty -F /dev/ttyUSB0 115200
sleep 1
exec xtensa-lx106-elf-gdb -x gdb_init_startup
