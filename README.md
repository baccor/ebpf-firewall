Ebpf firewall implemented as TC with a Go userspace controller.


Features:
- Map based rule storage
- Go userspace controller
- L3/L4 stateless packet filtering
- TCP/UDP support
- Source and destination ip/port filtering
- Ipv4 support  
- Default deny

What it does NOT have:
- Ipv6 support
- Wildcards for ANY port/ip
- Logging
- Rate limiting
- Connection tracking


To use it just run the makefile and build the go controller:

cd ebpf && make
cd ../go && go build -o fw .  
