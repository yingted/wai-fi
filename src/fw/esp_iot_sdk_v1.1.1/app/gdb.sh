#!/bin/sh
exec xtensa-lx106-elf-gdb -x gdb_init "$@"
