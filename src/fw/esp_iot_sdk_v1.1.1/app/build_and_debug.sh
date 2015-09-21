#!/bin/bash
set -e
GDB_STUB_STARTUP=1 ./build.sh
. flash_config.conf
esptool.py -b 921600 write_flash $flash_args 0x00000 ../bin/upgrade/boot.bin 0x01000 ../bin/upgrade/user1.4096.new.6.bin
#esptool.py -b 921600 write_flash $flash_args 0x00000 ../bin/upgrade/boot.bin 0x41000 ../bin/upgrade/user2.4096.new.6.bin
stty -F /dev/ttyUSB0 115200
#sleep 1
exec xtensa-lx106-elf-gdb -x gdb_init_startup
