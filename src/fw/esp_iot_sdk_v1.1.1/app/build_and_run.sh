#!/bin/bash
set -e
bash gen_misc.sh </dev/null
esptool.py -b 921600 write_flash -ff 80m 0x00000 ../bin/eagle.flash.bin 0x40000 ../bin/eagle.irom0text.bin
exec xtensa-lx106-elf-gdb -x gdb_init
