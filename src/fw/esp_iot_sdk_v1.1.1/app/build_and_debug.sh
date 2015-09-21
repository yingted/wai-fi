#!/bin/bash
set -e
. flash_config.conf
GDB_STUB_STARTUP=1 ./build.sh
esptool.py -b 921600 write_flash $flash_args 0x00000 ../bin/upgrade/boot.bin $start_addr ../bin/upgrade/user${build_userbin}.4096.new.6.bin
stty -F /dev/ttyUSB0 115200
#sleep 1
exec xtensa-lx106-elf-gdb -x gdb_init_startup
