#!/bin/bash
set -e
GDB_STUB_STARTUP=0 ./build.sh
esptool.py -b 921600 write_flash -ff 80m 0x00000 ../bin/upgrade/boot.bin 0x01000 ../bin/upgrade/user1.4096.new.6.bin
#esptool.py -b 921600 write_flash -ff 80m 0x00000 ../bin/upgrade/boot.bin 0x41000 ../bin/upgrade/user2.4096.new.6.bin
TERM=linux exec screen /dev/ttyUSB0 115200
