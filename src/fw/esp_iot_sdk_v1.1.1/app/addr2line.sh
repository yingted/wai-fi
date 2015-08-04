#!/bin/sh
grep -Eo '0x4[0-9a-f]{7}' "$@" | xtensa-lx106-elf-addr2line -aipsfe .output/eagle/debug/image/eagle.app.v6.out
