# Xpress DNS - Experimental XDP DNS server

## About
Xpress DNS is an experimental DNS server written in BPF for high throughput, low latency DNS responses.  
It uses [eXpress Data Path](https://en.wikipedia.org/wiki/Express_Data_Path) to process packets early in the Linux networking path.  
A user space application is provided to add DNS records to a BPF map which is read from in-kernel by the XDP module.  
DNS requests that do not match are passed on to the Linux networking stack. 

## Use case
Xpress DNS could be used as a high performance DNS proxy for common DNS requests of static DNS records.  
By responding to DNS requests before the packet gets processed by the Linux networking stack, it alleviates load on the system and DNS servers in user space.

## Features & limitations
* Currently supports A records
* Only supports plain DNS over UDP (port 53)
* Basic EDNS implementation
* Only responds to single queries for now
* No recursive lookups

## Requirements
* Kernel version 5.8 or higher is required as this program uses the `bpf_xdp_adjust_tail` call to extend packet size. See https://lwn.net/Articles/820562/, merged in 5.8.
* iproute2 to load the BPF object on a network device

## How to build
To build this software we use Docker to ensure a reproducable build environment.  
With Docker installed, run the `make` command in the root of the repository in order to build the software.

To build the software without Docker: install llvm, clang, libbpf-dev, iproute2 and run the `make` command in the `src` directory.

## How to use
Load the `xdp_dns_kern.o` BPF object using iproute2 on the target network interface (veth0 in the example below):
```bash
ip link set dev veth0 xdp obj ./src/xdp_dns_kern.o
```

Use the `xdns` user space application to manage DNS records.
```bash
Usage: xdns add record_type domain_name value [ttl]
       xdns remove record_type domain_name value
       xdns list
```
Example: ```xdns add a foo.bar 127.0.0.1 120```

Use `xdns list` to list all configured DNS records.

## How to test
Xpress DNS is compatible with BCC toolkit and can be instrumented with its Python bindings.  
You can refer to the supplied unit tests in [test_xdp_dns.py](src/test/test_xdp_dns.py) for pointers on how to test the code using BCC, scapy and Python's unit test module.

## License
This repository is licensed under GPLv2.0. 
See LICENSE file for details.
