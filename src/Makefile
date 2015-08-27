SUBDIRS = include fw/3rdparty/axtls
RECURSE = $(foreach SUBDIR,$(SUBDIRS),$(MAKE) -C $(SUBDIR) $(MAKECMDGOALS) &&) :

all: axtls.config
	git submodule update --init --recursive
	cp axtls.config fw/3rdparty/axtls/config/.config
	$(RECURSE)
clean:
	$(RECURSE)
.PHONY: all clean
