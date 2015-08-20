ifeq ($(GDB_STUB),1)
    DEFINES += -DGDB_STUB
    ifeq ($(GDB_STUB_STARTUP),1)
        DEFINES += -DGDB_STUB_STARTUP
    endif
    MY_LD_FILE = $(LD_FILE).ld-patched

%.ld.ld-patched: %.ld
	sed 's/\.irom0\.literal \.irom\.literal \.irom\.text\.literal \.irom0\.text \.irom\.text/& .irom0.text.* .irom0.literal.*/' $< > $@
	printf '_DebugExceptionVector = 0;\n' $(notdir $<) >> $@

else
	MY_LD_FILE = $(LD_FILE)
endif
