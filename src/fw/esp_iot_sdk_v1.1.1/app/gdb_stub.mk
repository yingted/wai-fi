ifeq ($(GDB_STUB),1)
    DEFINES += -DGDB_STUB
    ifeq ($(GDB_STUB_STARTUP),1)
        DEFINES += -DGDB_STUB_STARTUP
    endif
    MY_LD_FILE = $(LD_FILE).ld-patched

%.ld.ld-patched: %.ld
	printf 'INCLUDE "%q"\n_DebugExceptionVector = 0;\n' $(notdir $<) >> $@
else
	MY_LD_FILE = $(LD_FILE)
endif
