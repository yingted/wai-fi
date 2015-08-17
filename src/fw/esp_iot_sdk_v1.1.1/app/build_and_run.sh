#!/bin/bash
set -e
GDB_STUB_STARTUP=0 bash gen_misc.sh < build_config.txt
esptool.py -b 921600 write_flash -ff 80m 0x00000 ../bin/eagle.flash.bin 0x40000 ../bin/eagle.irom0text.bin
TERM=linux exec screen /dev/ttyUSB0 115200
