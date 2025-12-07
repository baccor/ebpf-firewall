package initfrwl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const ips = "/sys/fs/bpf/fw_ips"
const ipss = "/sys/fs/bpf/fw_ipss"
const ipsd = "/sys/fs/bpf/fw_ipsd"

type keyc struct {
	Src   uint32
	Dst   uint32
	Sprt  uint16
	Dprt  uint16
	Prtcl uint8
	Pad   [3]byte
}

type kssd struct {
	IP    uint32
	Prt   uint16
	Prtcl uint8
	Pad   uint8
}

type Maps struct {
	Ips  *ebpf.Map
	Ipss *ebpf.Map
	Ipsd *ebpf.Map
}

func Init(pth, intf, igeg string) error {
	spec, err := ebpf.LoadCollectionSpec(pth)
	if err != nil {
		return fmt.Errorf("error loading collection spec %q: %v", pth, err)
	}

	var col *ebpf.Collection

	mps, err := Omaps()
	if err == nil {
		defer mps.Close()

		col, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"ips":  mps.Ips,
				"ipss": mps.Ipss,
				"ipsd": mps.Ipsd,
			},
		})
		if err != nil {
			return fmt.Errorf("error creating collection with replacements: %v", err)
		}
		log.Println("reusing existing pinned maps /sys/fs/bpf/fw_*")
	} else {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("error checking pinned map %s: %w", ips, err)
		}

		col, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: "/sys/fs/bpf",
			},
		})
		if err != nil {
			return fmt.Errorf("error creating collection: %v", err)
		}

		pinMap := func(name, path string) error {
			m, ok := col.Maps[name]
			if !ok {
				return fmt.Errorf("error: map %q not found in %s", name, pth)
			}
			if err := m.Pin(path); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("error pinning %s -> %s: %w", name, path, err)
				}
			}
			return nil
		}

		if err := pinMap("ips", ips); err != nil {
			return err
		}
		if err := pinMap("ipss", ipss); err != nil {
			return err
		}
		if err := pinMap("ipsd", ipsd); err != nil {
			return err
		}

		log.Println("maps pinned under /sys/fs/bpf/fw_*")
	}

	defer col.Close()

	if intf == "" || igeg == "" {
		log.Println("initialized firewall maps only (no attach)")
		return nil
	}

	nlLink, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("error getting link %q: %v", intf, err)
	}
	ifIndex := nlLink.Attrs().Index

	ob, ok := col.Programs["frwll"]
	if !ok {
		return fmt.Errorf("program 'frwll' not found in %s", pth)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			log.Printf("warning: qdisc add error: %v", err)
		}
	}

	ineg := netlink.HANDLE_MIN_INGRESS
	if igeg == "egress" {
		ineg = netlink.HANDLE_MIN_EGRESS
	}

	fltr := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    uint32(ineg),
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
			Protocol:  unix.ETH_P_IP,
		},
		Fd:           ob.FD(),
		Name:         "frwll",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(fltr); err != nil {
		return fmt.Errorf("error attaching BPF filter: %v", err)
	}

	log.Printf("attached frwll to %s %s", intf, igeg)
	return nil
}

func Attach(pth, intf, igeg string) error {
	if intf == "" || igeg == "" {
		return fmt.Errorf("attach: interface and direction (ingress|egress) must be provided")
	}

	nlLink, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("error getting link %q: %v", intf, err)
	}
	ifIndex := nlLink.Attrs().Index

	spec, err := ebpf.LoadCollectionSpec(pth)
	if err != nil {
		return fmt.Errorf("error loading collection spec %q: %v", pth, err)
	}

	mps, err := Omaps()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("attach: pinned map %s does not exist (run init/prepare first)", ips)
		}
		return fmt.Errorf("attach: error opening %s: %w", ips, err)
	}
	defer mps.Close()

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"ips":  mps.Ips,
			"ipss": mps.Ipss,
			"ipsd": mps.Ipsd,
		},
	})
	if err != nil {
		return fmt.Errorf("error creating collection with replacements: %v", err)
	}
	defer col.Close()

	ob, ok := col.Programs["frwll"]
	if !ok {
		return fmt.Errorf("program 'frwll' not found in %s", pth)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			log.Printf("warning: qdisc add error: %v", err)
		}
	}

	ineg := netlink.HANDLE_MIN_INGRESS
	if igeg == "egress" {
		ineg = netlink.HANDLE_MIN_EGRESS
	}

	fltr := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    uint32(ineg),
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
			Protocol:  unix.ETH_P_IP,
		},
		Fd:           ob.FD(),
		Name:         "frwll",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(fltr); err != nil {
		return fmt.Errorf("error attaching BPF filter: %v", err)
	}

	log.Printf("attached frwll to %s %s using existing pinned maps", intf, igeg)
	return nil
}

func Rem(intf, igeg string) error {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("error getting link %q: %v", intf, err)
	}

	parent := uint32(netlink.HANDLE_MIN_INGRESS)
	if igeg == "egress" {
		parent = netlink.HANDLE_MIN_EGRESS
	}

	fl, err := netlink.FilterList(link, parent)
	if err != nil {
		return fmt.Errorf("error listing filters on %s %s: %v", intf, igeg, err)
	}

	is := false
	for _, f := range fl {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		if bf.Name != "frwll" {
			continue
		}

		if err := netlink.FilterDel(bf); err != nil {
			return fmt.Errorf("error detaching frwll from %s %s: %v", intf, igeg, err)
		}

		is = true
		log.Printf("detached frwll from %s %s", intf, igeg)
	}

	if !is {
		log.Printf("no frwll filter found on %s %s", intf, igeg)
	}

	return nil
}

func Clr() error {
	paths := []string{ips, ipss, ipsd}

	for _, p := range paths {
		m, err := ebpf.LoadPinnedMap(p, nil)
		if err != nil {
			return fmt.Errorf("error opening map %s: %w", p, err)
		}

		switch p {
		case ips:
			it := m.Iterate()
			var k keyc
			var v uint32
			for it.Next(&k, &v) {
				if err := m.Delete(&k); err != nil {
					m.Close()
					return fmt.Errorf("error deleting from %s: %w", p, err)
				}
			}
			if err := it.Err(); err != nil {
				m.Close()
				return fmt.Errorf("error iterating %s: %w", p, err)
			}

		case ipss, ipsd:
			it := m.Iterate()
			var k kssd
			var v uint32
			for it.Next(&k, &v) {
				if err := m.Delete(&k); err != nil {
					m.Close()
					return fmt.Errorf("error deleting from %s: %w", p, err)
				}
			}
			if err := it.Err(); err != nil {
				m.Close()
				return fmt.Errorf("error iterating %s: %w", p, err)
			}
		}

		m.Close()
	}

	return nil
}

func Ip(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		log.Fatalf("not an ipv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip)
}

func Ips(s string) []uint32 {
	if ip := net.ParseIP(s); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			log.Fatalf("not an ipv4: %s", s)
		}
		a := binary.LittleEndian.Uint32(ip4)
		return []uint32{a}
	}

	ips, err := net.LookupIP(s)
	if err != nil {
		return nil
	}
	var k []uint32
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		p := binary.LittleEndian.Uint32(ip4)
		k = append(k, p)
	}

	if len(k) == 0 {
		return nil
	}
	return k

}

func Prt(s string) uint16 {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		log.Fatalf("invalid port %q", s)
	}
	prt := uint16(p)
	return (prt >> 8) | (prt << 8)
}

func Omaps() (*Maps, error) {
	ips, err := ebpf.LoadPinnedMap("/sys/fs/bpf/fw_ips", nil)
	if err != nil {
		return nil, err
	}

	ipss, err := ebpf.LoadPinnedMap("/sys/fs/bpf/fw_ipss", nil)
	if err != nil {
		ips.Close()
		return nil, err
	}

	ipsd, err := ebpf.LoadPinnedMap("/sys/fs/bpf/fw_ipsd", nil)
	if err != nil {
		ips.Close()
		ipss.Close()
		return nil, err
	}

	return &Maps{Ips: ips, Ipss: ipss, Ipsd: ipsd}, nil
}

func (mps *Maps) Close() {
	mps.Ips.Close()
	mps.Ipss.Close()
	mps.Ipsd.Close()
}
func Dst(args []string, mps *Maps) {
	if len(os.Args) != 4 && len(os.Args) != 5 {
		log.Fatalf("usage: fw dst <ip> <port> [tcp/udp]")
	}
	d := uint32(1)

	prt := Prt(os.Args[3])
	ips := Ips(os.Args[2])
	if ips == nil {
		log.Fatalf("no IPv4 addresses resolved for %q", os.Args[2])
	}

	prtcl := uint8(6)
	if len(os.Args) == 5 {
		if os.Args[4] == "udp" {
			prtcl = uint8(17)
		}
	}

	for _, ip := range ips {
		k := kssd{
			IP:    ip,
			Prt:   prt,
			Prtcl: prtcl,
			Pad:   0,
		}
		if err := mps.Ipsd.Put(k, d); err != nil {
			log.Fatalf("error putting dst rule for %v: %v", ip, err)
		}
	}
	log.Println("dst rule applied")
}

func Rule(args []string, mps *Maps) {
	if len(os.Args) != 6 && len(os.Args) != 7 {
		log.Fatalf("usage: fw rule <src_ip> <src_port> <dst_ip> <dst_port> [tcp/udp]")
	}
	d := uint32(1)

	if net.ParseIP(os.Args[2]) == nil || net.ParseIP(os.Args[4]) == nil {
		log.Fatalf("invalid IP(s)")
	}

	prtcl := uint8(6)
	if len(os.Args) == 5 {
		if os.Args[6] == "udp" {
			prtcl = uint8(17)
		}
	}

	src := Ip(os.Args[2])
	sprt := Prt(os.Args[3])
	dst := Ip(os.Args[4])
	dprt := Prt(os.Args[5])

	key := keyc{
		Src:   src,
		Dst:   dst,
		Sprt:  sprt,
		Dprt:  dprt,
		Prtcl: prtcl,
		Pad:   [3]byte{},
	}

	if err := mps.Ips.Put(key, d); err != nil {
		log.Fatalf("error putting rule: %v", err)
	}
	log.Println("rule applied")
}

func Src(args []string, mps *Maps) {
	if len(os.Args) != 4 && len(os.Args) != 5 {
		log.Fatalf("usage: fw src <ip> <port> [tcp/udp]")
	}
	d := uint32(1)
	prt := Prt(os.Args[3])
	ips := Ips(os.Args[2])
	if ips == nil {
		log.Fatalf("no IPv4 addresses resolved for %q", os.Args[2])
	}

	prtcl := uint8(6)
	if len(os.Args) == 5 {
		if os.Args[4] == "udp" {
			prtcl = uint8(17)
		}
	}

	for _, ip := range ips {
		k := kssd{
			IP:    ip,
			Prt:   prt,
			Prtcl: prtcl,
			Pad:   0,
		}
		if err := mps.Ipss.Put(k, d); err != nil {
			log.Fatalf("error putting src rule for %v: %v", ip, err)
		}
	}
	log.Println("src rule applied")
}
