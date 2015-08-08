#############################################################
# Required variables for each makefile
# Discard this section from all parent makefiles
# Expected variables (with automatic defaults):
#   CSRCS (all "C" files in the dir)
#   SUBDIRS (all subdirs with a Makefile)
#   GEN_LIBS - list of libs to be generated ()
#   GEN_IMAGES - list of object file images to be generated ()
#   GEN_BINS - list of binaries to be generated ()
#   COMPONENTS_xxx - a list of libs/objs in the form
#     subdir/lib to be extracted and rolled up into
#     a generated lib/image xxx.a ()
#
TARGET = eagle
# Additional logging is disabled in release mode.
#FLAVOR = release
FLAVOR = debug
# Assertions and stuff. Big performance penalty.
DEBUG_ESP ?= 1
# Allow debugging using gdb.sh and friends.
GDB_STUB ?= 1
# Code in a breakpoint at the start of user_init.
GDB_STUB_STARTUP ?= 0
ifneq ($(GDB_STUB),1)
    GDB_STUB_STARTUP = 0
endif

#EXTRA_CCFLAGS += -u

ifndef PDIR # {
GEN_IMAGES= eagle.app.v6.out
GEN_BINS= eagle.app.v6.bin
SPECIAL_MKTARGETS=$(APP_MKTARGETS)
SUBDIRS=    \
	user

endif # } PDIR

APPDIR = .
LDDIR = ../ld

CCFLAGS += -MMD -flto -include ../include/user_config.h

ifeq ($(FLAVOR),release)
	DEFINES += -DNDEBUG
	DEBUG_ESP = 0
    GDB_STUB = 0
endif
ifeq ($(GDB_STUB),1)
    #DEBUG_ESP = 0
endif

# Now, we need to use MY_LD_FILE instead of LD_FILE
include $(or $(PDIR),$(PWD))/gdb_stub.mk

TARGET_LDFLAGS =		\
	-nostdlib		\
	-Wl,-EL \
	--longcalls \
	-flto \
	--text-section-literals

ifeq ($(FLAVOR),debug)
    TARGET_LDFLAGS += -ggdb3 -O0
    CCFLAGS += -O0 -ggdb3
endif

ifeq ($(FLAVOR),release)
    TARGET_LDFLAGS += -O2
    CCFLAGS += -Os
endif

COMPONENTS_eagle.app.v6 = \
	user/libuser.a

LINKFLAGS_eagle.app.v6 = \
	-nostdlib	\
	-T$(MY_LD_FILE)   \
	-Wl,--no-check-sections	\
	-u call_user_start	\
	-Wl,-static						\
	-Wl,--start-group					\
	-lgcc					\
	-lhal					\
	-lphy	\
	-lpp	\
	-lnet80211	\
	-llwip	\
	-lwpa	\
	-lmain	\
	-lssl	\
	$(DEP_LIBS_eagle.app.v6)					\
	-Wl,--end-group

#	-lupgrade	\
#	-lc					\
#	-ljson	\
#	-lsmartconfig \

DEPENDS_eagle.app.v6 = \
                $(MY_LD_FILE) \
                $(LDDIR)/eagle.rom.addr.v6.ld

#############################################################
# Configuration i.e. compile options etc.
# Target specific stuff (defines etc.) goes in here!
# Generally values applying to a tree are captured in the
#   makefile at its root level - these are then overridden
#   for a subtree within the makefile rooted therein
#

#UNIVERSAL_TARGET_DEFINES =		\

# Other potential configuration flags include:
#	-DTXRX_TXBUF_DEBUG
#	-DTXRX_RXBUF_DEBUG
#	-DWLAN_CONFIG_CCX
CONFIGURATION_DEFINES =	-DICACHE_FLASH

DEFINES +=				\
	$(UNIVERSAL_TARGET_DEFINES)	\
	$(CONFIGURATION_DEFINES)

DDEFINES +=				\
	$(UNIVERSAL_TARGET_DEFINES)	\
	$(CONFIGURATION_DEFINES)


#############################################################
# Recursion Magic - Don't touch this!!
#
# Each subtree potentially has an include directory
#   corresponding to the common APIs applicable to modules
#   rooted at that subtree. Accordingly, the INCLUDE PATH
#   of a module can only contain the include directories up
#   its parent path, and not its siblings
#
# Required for each makefile to inherit from the parent
#

INCLUDES := $(INCLUDES) -I $(PDIR)include

# ICMP hook
WRAP := \
	-Wl,-wrap,icmp_input \
	-Wl,-wrap,sys_check_timeouts \
	-Wl,-wrap,pvPortMalloc \
	-Wl,-wrap,ssl_ctx_new \
	-Wl,-wrap,ssl_ctx_free \
	-Wl,-wrap,sta_input \

ifeq ($(DEBUG_ESP),1)
	DEFINES += -DDEBUG_ESP
	WRAP += \
		-Wl,-wrap,esf_buf_alloc \
		-Wl,-wrap,esf_rx_buf_alloc \
		-Wl,-wrap,mem_malloc \
		-Wl,-wrap,mem_realloc \
		-Wl,-wrap,inet_chksum_pseudo \
		-Wl,-wrap,inet_chksum_pseudo_partial \
		-Wl,-wrap,inet_chksum \
		-Wl,-wrap,inet_chksum_pbuf \
		-Wl,-wrap,ip_input \
		-Wl,-wrap,etharp_tmr \

endif

LINKFLAGS_eagle.app.v6 += \
	$(WRAP) \
	-fdata-sections -ffunction-sections -Wl,--gc-sections \

INCLUDES += -I $(PDIR)../../3rdparty/esp_iot_rtos_sdk/include
INCLUDES += -I $(PDIR)../../3rdparty/esp_iot_rtos_sdk/include/lwip
INCLUDES += -I $(PDIR)../../3rdparty/esp_iot_rtos_sdk/include/lwip/ipv4
INCLUDES += -I $(PDIR)../../3rdparty/esp_iot_rtos_sdk/include/lwip/ipv6
INCLUDES += -I $(PDIR)../../3rdparty/esp_iot_rtos_sdk/extra_include


PDIR := ../$(PDIR)
sinclude $(PDIR)Makefile

.PHONY: FORCE
FORCE:

