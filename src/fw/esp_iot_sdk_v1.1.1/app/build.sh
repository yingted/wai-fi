#!/bin/bash
exec bash gen_misc.sh < <(
# STEP 1: choose boot version(0=boot_v1.1, 1=boot_v1.2+, 2=none)
# enter(0/1/2, default 2):
echo 1

# STEP 2: choose bin generate(0=eagle.flash.bin+eagle.irom0text.bin, 1=user1.bin, 2=user2.bin)
# enter (0/1/2, default 0):
echo ${BUILD_USERBIN:-1}

# STEP 3: choose spi speed(0=20MHz, 1=26.7MHz, 2=40MHz, 3=80MHz)
# enter (0/1/2/3, default 2):
echo 3

# STEP 4: choose spi mode(0=QIO, 1=QOUT, 2=DIO, 3=DOUT)
# enter (0/1/2/3, default 0):
echo 0

# STEP 5: choose spi size and map
#     0= 512KB( 256KB+ 256KB)
#     2=1024KB( 512KB+ 512KB)
#     3=2048KB( 512KB+ 512KB)
#     4=4096KB( 512KB+ 512KB)
#     5=2048KB(1024KB+1024KB)
echo 5
#     6=4096KB(1024KB+1024KB)
# enter (0/2/3/4/5/6, default 0):
)
