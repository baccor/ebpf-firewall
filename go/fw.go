package main

import (
	"frwl/dae"
	initfrwl "frwl/init"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 5 {
		log.Fatalf("\nusage: fw init <ebpf.o> <interface> ingress|egress\nfw attach <ebpf.o> <interface> ingress|egress\nfw remove <interface> ingress|egress\nfw clear\nfw src ip/cidr:port [TCP/UDP]\nfw dst ip/cidr:port [TCP/UDP]\nfw rule srcip/cidr:port dstip/cidr:port [TCP/UDP]")
	}

	if os.Args[1] != "dae" {
		if err := dae.Rundae(); err != nil {
			log.Fatalf("error initializing daemon: %v", err)
		}
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

	switch os.Args[1] {

	case "dae":
		if err := dae.Daeinit(); err != nil {
			log.Fatalf("error running daemon: %v", err)
		}
		select {}
	case "src":
		if err := initfrwl.Src(os.Args); err != nil {
			log.Fatalf("error adding src: %v", err)
		}
		os.Exit(0)
	case "dst":
		if err := initfrwl.Dst(os.Args); err != nil {
			log.Fatalf("error adding dst: %v", err)
		}
		os.Exit(0)
	case "rule":
		if err := initfrwl.Rule(os.Args); err != nil {
			log.Fatalf("error adding rule: %v", err)
		}
		os.Exit(0)

	case "log":
		if err := initfrwl.Log(os.Args); err != nil {
			log.Fatalf("log error: %v", err)
		}
		os.Exit(0)
	case "clear":
		if err := initfrwl.Clr(os.Args); err != nil {
			log.Fatalf("error clearing rule: %v", err)
		}
		os.Exit(0)
	case "attach":
		if len(os.Args) != 5 {
			log.Fatalf("usage: fw attach <ebpf.o> <interface> ingress|egress")
		}
		if err := initfrwl.Attach(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			log.Fatalf("error attaching frwll: %v", err)
		}
		os.Exit(0)

	default:
		log.Fatalf("\nusage: fw init <ebpf.o> <interface> ingress|egress\nfw attach <ebpf.o> <interface> ingress|egress\nfw remove <interface> ingress|egress\nfw clear\nfw src ip/cidr:port [TCP/UDP]\nfw dst ip/cidr:port [TCP/UDP]\nfw rule srcip/cidr:port dstip/cidr:port [TCP/UDP]")
	}
}
