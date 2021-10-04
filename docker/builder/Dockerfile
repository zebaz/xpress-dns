FROM debian:bullseye
RUN apt-get update && apt-get install -y make clang-11 llvm-11 libc6-dev libc6-dev-i386 libz-dev libelf-dev libbpf-dev iproute2 && apt-get clean
RUN ln -s $(which clang-11) /usr/bin/clang && ln -s $(which llc-11) /usr/bin/llc
#For testing
# RUN apt-get update && apt-get install -y python3 python3-scapy python3-bpfcc linux-headers-$(uname -r)
#For debugging
# RUN DEBIAN_FRONTEND=noninteractive apt install -y strace bpftool lldb scapy tmux dnsutils tcpdump tshark termshark nano
