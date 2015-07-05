
#############################################################
# Required variables for each makefile
# Discard this section from all parent makefiles
# Expected variables (with automatic defaults):
#   CSRCS (all "C" files in the dir)
#   SUBDIRS (all subdirs with a Makefile)
#   GEN_LIBS - list of libs to be generated ()
#   GEN_IMAGES - list of images to be generated ()
#   COMPONENTS_xxx - a list of libs/objs in the form
#     subdir/lib to be extracted and rolled up into
#     a generated lib/image xxx.a ()
#
ifndef PDIR
GEN_LIBS = libuser.a
endif


#############################################################
# Configuration i.e. compile options etc.
# Target specific stuff (defines etc.) goes in here!
# Generally values applying to a tree are captured in the
#   makefile at its root level - these are then overridden
#   for a subtree within the makefile rooted therein
#
#DEFINES += 

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
INCLUDES += -I ./
INCLUDES += -I ../../include/ets
PDIR := ../$(PDIR)
sinclude $(PDIR)Makefile

default_private_key default_ca_private_key:
	openssl genrsa 1024 | openssl rsa -outform DER -out $@

cert_req.csr: default_private_key cert_req.txt
	openssl req -new -key $< -keyform DER -out $@ < cert_req.txt

default_ca_certificate: default_ca_private_key
	openssl req -x509 -new -nodes -key $< -keyform DER -days 12000 -out $@ -outform DER < ca_req.txt

default_certificate: cert_req.csr default_ca_certificate default_ca_private_key
	openssl x509 -req -days 12000 -in $< -CA default_ca_certificate -CAform DER -CAkey default_ca_private_key -CAkeyform DER -CAcreateserial -out $@ -outform DER

default_ca_certificate.pem: default_ca_certificate
	openssl x509 -in $< -inform DER -out $@

default_ca_private_key.pem: default_ca_private_key
	openssl rsa -in $< -inform DER -out $@

CERTFILES = default_private_key.c default_certificate.c default_ca_certificate.c

$(CERTFILES): %.c: %
	xxd -i $< > $@

# XXX these don't get auto-run
CSRCS += $(CERTFILES)
OBJS += $(CERTFILES:%.c=$(OBJODIR)/%.o)
certfiles: $(CERTFILES)
.PHONY: certfiles
