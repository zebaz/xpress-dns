# Makefile for building xdp_dns in a Docker container

#DEBUG = y  enables printk in the BPF program
DEBUG ?= n

all: builder xdp_dns

builder:
	docker build -t bpf-builder:latest docker/builder

xdp_dns: builder
	docker run --rm -ti -v$(shell pwd):/input -v$(shell pwd)/build:/output \
	bpf-builder sh -c "cd /input/src && make DEBUG=$(DEBUG)"

test: xdp_dns_kern
	docker run --privileged -ti -v $(shell pwd):/input bpf-builder ./input/test.sh

clean:
	docker rmi bpf-builder
	make -C ./src clean
