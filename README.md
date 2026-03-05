Ebpf firewall implemented as TC with a Go userspace controller.


Features:
- Map based rule storage
- Go userspace controller
- L3/L4 stateless packet filtering
- TCP/UDP support
- Wildcard support
- Ipv4 support
- Default deny
- Daemon log exporter

What it does NOT have:
- Ipv6 support
- Rate limiting
- Connection tracking


To use it just run the makefile and build the go controller:

(replace vmlinux.h first though: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h) 

cd ebpf && make
 
cd ../go && go build -o fw .


Requirements:
- Linux kernel with BTF
- Clang with ebpf target support
- bpftool (for regenerating vmlinux.h)
- Kernel / libbpf headers providing:
- bpf/bpf_helpers.h
- bpf/bpf_endian.h
- Go
- Sudo


Currently mid testing.
