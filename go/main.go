package main

import (
	initfrwl "frwll/init"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("\nusage: fw init <ebpf.o> <interface> ingress|egress\nfw attach <ebpf.o> <interface> ingress|egress\nfw remove <interface> ingress|egress\nfw clear\nfw src <ip> <port>\nfw dst <ip> <port>\nfw rule <src_ip> <src_port> <dst_ip> <dst_port>")
	}

	if os.Args[1] == "init" {
		if len(os.Args) == 3 {
			if err := initfrwl.Init(os.Args[2], "", ""); err != nil {
				log.Fatalf("error initializing firewall maps: %v", err)
			}
			os.Exit(0)
		}

		if len(os.Args) == 5 {
			if err := initfrwl.Init(os.Args[2], os.Args[3], os.Args[4]); err != nil {
				log.Fatalf("error initializing firewall: %v", err)
			}
			os.Exit(0)
		}

		log.Fatalf("usage: fw init <ebpf.o> OR fw init <ebpf.o> <interface> ingress|egress")
	}
	if os.Args[1] == "remove" && len(os.Args) == 4 {
		if err := initfrwl.Rem(os.Args[2], os.Args[3]); err != nil {
			log.Fatalf("error removing frwll %s from interface %s: %v", os.Args[3], os.Args[2], err)
		}
		os.Exit(0)
	}
	if os.Args[1] == "clear" && len(os.Args) == 2 {
		if err := initfrwl.Clr(); err != nil {
			log.Fatalf("error clearing maps: %v", err)
		}
		os.Exit(0)
	}

	mps, err := initfrwl.Omaps()
	if err != nil {
		log.Fatal(err)
	}
	defer mps.Close()

	switch os.Args[1] {
	case "src":
		initfrwl.Src(os.Args, mps)
	case "dst":
		initfrwl.Dst(os.Args, mps)
	case "rule":
		initfrwl.Rule(os.Args, mps)
	case "attach":
		if len(os.Args) != 5 {
			log.Fatalf("usage: fw attach <ebpf.o> <interface> ingress|egress")
		}
		if err := initfrwl.Attach(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			log.Fatalf("error attaching frwll: %v", err)
		}

	default:
		log.Fatalf("\nusage: fw init <ebpf.o> <interface> ingress|egress\nfw attach <ebpf.o> <interface> ingress|egress\nfw remove <interface> ingress|egress\nfw clear\nfw src <ip> <port>\nfw dst <ip> <port>\nfw rule <src_ip> <src_port> <dst_ip> <dst_port>")
	}
}
