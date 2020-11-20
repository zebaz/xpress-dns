# SPDX-License-Identifier: GPL-2.0-or-later
# --------------------------------------------------
# Makefile for xdp_dns
# --------------------------------------------------
CLANG = clang
LLC = llc
#DEBUG = y  enables printk in the BPF program
DEBUG ?= n

#Path to include files of respectively libbpf-dev and iproute2
LIBBPF_INCLUDE ?= /usr/include/bpf
IPROUTE_INCLUDE ?= /usr/include/iproute2

SRC_DIR=.
#vpath %.c $(SRC_DIR)
#vpath %.h $(SRC_DIR)

LIBBPF_DIR ?= /usr/lib/$(shell uname -m)-linux-gnu
#Requires libbpf-dev package
OBJECT_LIBBPF = libbpf.a

CFLAGS ?= -I$(LIBBPF_INCLUDE) -I $(IPROUTE_INCLUDE) -g -static
LDFLAGS ?= -L$(LIBBPF_DIR)
LDLIBS ?= -l:libbpf.a -lelf -lz

BPF_CFLAGS ?= -I $(LIBBPF_INCLUDE) \
		-I $(IPROUTE_INCLUDE)

ifeq ($(DEBUG),y)
	BPF_EXTRA_FLAGS += -D DEBUG
endif

all: llvm-check xdp_dns_kern xdp_dns

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -f *.o
	rm -f *.ll
	rm -f *~

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

xdp_dns: %: %.c Makefile
	$(CLANG) \
            -Wall \
            $(CFLAGS) \
            $(LDFLAGS) \
            -o xdns \
	    $< $(LDLIBS)

xdp_dns_kern: %: %.c Makefile
	$(CLANG) \
	    -target bpf \
	    $(BPF_CFLAGS) \
	    -Wall $(BPF_EXTRA_FLAGS) \
            -O2 -c -o $@.o $<
