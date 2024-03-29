# Makefile for building xdp_dns in a Docker container

#DEBUG = y  enables printk in the BPF program
DEBUG ?= n
#Compiler flags for specific DNS features
EDNS ?= y #RFC6891

all: builder xdp_dns

builder:
	docker build -t bpf-builder:latest docker/builder

xdp_dns: builder
	docker run --rm -ti -v$(shell pwd):/input -v$(shell pwd)/build:/output \
       	bpf-builder sh -c "cd /input/src && make DEBUG=$(DEBUG) FEATURE_EDNS=$(EDNS)"

test: builder
	docker run --privileged --rm -ti -v$(shell pwd):/input -v$(shell pwd)/build:/output \
	bpf-builder sh -c "cd /input/src && python3 test/test_xdp_dns.py"

clean:
	docker rmi bpf-builder
	make -C ./src clean
