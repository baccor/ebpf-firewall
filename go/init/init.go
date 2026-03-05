package initfrwl

import (
	"bufio"
	"errors"
	"fmt"
	"frwl/dae"
	"io/fs"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const srcpth = "/sys/fs/bpf/fw_src"
const rlespth = "/sys/fs/bpf/fw_rles"
const dstpth = "/sys/fs/bpf/fw_dst"
const skt = "/var/tmp/frwll/frwlld.sock"

type key struct {
	id    uint64
	sprt  uint16
	dprt  uint16
	prtcl uint8
	wc    uint8
}

type Maps struct {
	src    *ebpf.Map
	dst    *ebpf.Map
	rles   *ebpf.Map
	islogs *ebpf.Map
	logs   *ebpf.Map
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
				"fw_rles":   mps.rles,
				"fw_src":    mps.src,
				"fw_dst":    mps.dst,
				"fw_islogs": mps.islogs,
				"fw_logs":   mps.logs,
			},
		})
		if err != nil {
			return fmt.Errorf("error creating collection with replacements: %v", err)
		}
		log.Println("reusing existing pinned maps /sys/fs/bpf/fw_*")
	} else {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("error checking pinned map %s: %w", rlespth, err)
		}

		col, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: "/sys/fs/bpf",
			},
		})
		if err != nil {
			return fmt.Errorf("error creating collection: %v", err)
		}

		if err := dae.Globalfb(); err != nil {
			return fmt.Errorf("error adding global fallbacks: %v", err)
		}

		log.Println("maps pinned under /sys/fs/bpf/fw_*")

	}

	defer col.Close()

	if intf == "" || igeg == "" {
		log.Println("initialized firewall maps only (no attach)")
		return nil
	}

	if err := dae.Rundae(); err != nil {
		return fmt.Errorf("error running daemon.")
	}

	log.Println("daemon running.")

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
			return fmt.Errorf("attach: pinned map %s does not exist (run init/prepare first)", rlespth)
		}
		return fmt.Errorf("attach: error opening %s: %w", rlespth, err)
	}
	defer mps.Close()

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"fw_rles":   mps.rles,
			"fw_src":    mps.src,
			"fw_dst":    mps.dst,
			"fw_islogs": mps.islogs,
			"fw_logs":   mps.logs,
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

func Clrall() error { //for later
	paths := []string{rlespth, srcpth, dstpth}

	for _, p := range paths {
		m, err := ebpf.LoadPinnedMap(p, nil)
		if err != nil {
			return fmt.Errorf("error opening map %s: %w", p, err)
		}

		switch p {
		case rlespth:
			it := m.Iterate()
			var k key
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

		case srcpth, dstpth:
			it := m.Iterate()
			var k key
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

/*func Ip(s string) uint32 {
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
} */

func Omaps() (*Maps, error) {
	ips, err := ebpf.LoadPinnedMap("/sys/fs/bpf/fw_rles", nil)
	if err != nil {
		return nil, err
	}

	ipss, err := ebpf.LoadPinnedMap("/sys/fs/bpf/fw_src", nil)
	if err != nil {
		ips.Close()
		return nil, err
	}

	ipsd, err := ebpf.LoadPinnedMap("/sys/fs/bpf/fw_dst", nil)
	if err != nil {
		ips.Close()
		ipss.Close()
		return nil, err
	}

	ilgs, err := ebpf.LoadPinnedMap("/sys/fs/bpf/fw_islogs", nil)
	if err != nil {
		ips.Close()
		ipss.Close()
		return nil, err
	}

	lgs, err := ebpf.LoadPinnedMap("/sys/fs/bpf/fw_logs", nil)
	if err != nil {
		ips.Close()
		ipss.Close()
		return nil, err
	}

	return &Maps{rles: ips, src: ipss, dst: ipsd, islogs: ilgs, logs: lgs}, nil
}

func (mps *Maps) Close() {
	mps.rles.Close()
	mps.src.Close()
	mps.dst.Close()
}
func Dst(args []string) error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: fw dst ip{/cidr}:port [TCP/UDP]")
	}
	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, "dst", os.Args[2], os.Args[3]); err != nil {
		return fmt.Errorf("error: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "added":
		return nil
	case "error":
		if len(parts) >= 2 {
			return fmt.Errorf("daemon error: %s", parts[1:])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}
}

func Rule(args []string) error {
	if len(os.Args) != 5 {
		return fmt.Errorf("usage: fw rule src_ip/cidr:port dst_ip/cidr:port [TCP/UDP]")
	}
	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, "rule", os.Args[2], os.Args[3], os.Args[4]); err != nil {
		return fmt.Errorf("error: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "added":
		return nil
	case "error":
		if len(parts) >= 2 {
			return fmt.Errorf("daemon error: %s", parts[1:])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}
}

func Src(args []string) error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: fw src_ip{/cidr}:port [tcp/udp]")
	}
	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, "src", os.Args[2], os.Args[3]); err != nil {
		return fmt.Errorf("error: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "added":
		return nil
	case "error":
		if len(parts) >= 2 {
			return fmt.Errorf("daemon error: %s", parts[1:])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}
}

func Clr(args []string) error {
	if len(os.Args) != 5 && len(os.Args) != 6 {
		return fmt.Errorf("usage: fw clear src... || dst... || rule... ")
	}
	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	switch os.Args[2] {

	case "src":
		if _, err := fmt.Fprintln(conn, "clear", "src", os.Args[3], os.Args[4]); err != nil {
			return fmt.Errorf("error: %w", err)
		}

	case "dst":
		if _, err := fmt.Fprintln(conn, "clear", "dst", os.Args[3], os.Args[4]); err != nil {
			return fmt.Errorf("error: %w", err)
		}

	case "rule":
		if _, err := fmt.Fprintln(conn, "clear", "rule", os.Args[3], os.Args[4], os.Args[5]); err != nil {
			return fmt.Errorf("error: %w", err)
		}

	default:
		return fmt.Errorf("unknown command.")

	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "cleared":
		return nil
	case "error":
		if len(parts) >= 2 {
			return fmt.Errorf("daemon error: %s", parts[1:])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}
}

func Log(args []string) error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: fw log on||off||export||stop")
	}
	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, "log", os.Args[2]); err != nil {
		return fmt.Errorf("error: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "done":
		return nil
	case "error":
		if len(parts) >= 2 {
			return fmt.Errorf("daemon error: %s", parts[1:])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}
}
