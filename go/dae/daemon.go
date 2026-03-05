package dae

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"frwl/logs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

const skt = "/var/tmp/frwll/frwlld.sock"
const state = "/var/tmp/frwll/state.json"
const srcpth = "/sys/fs/bpf/fw_src"
const rlespth = "/sys/fs/bpf/fw_rles"
const dstpth = "/sys/fs/bpf/fw_dst"

type State struct {
	NextID uint32            `json:"next_id"`
	Src    map[string]uint32 `json:"src"`
	Dst    map[string]uint32 `json:"dst"`
	Rules  []Rule            `json:"rules"`
}

type lpmv4 struct {
	pfxlen uint32
	ipv4   uint32
}

type Rule struct {
	SrcID uint32 `json:"src_id"`
	DstID uint32 `json:"dst_id"`
	Sprt  uint16 `json:"sport"`
	Dprt  uint16 `json:"dport"`
	Prtcl uint8  `json:"proto"`
	Wc    uint8  `json:"wc"`
}

var (
	Expctx  context.Context
	Expcanc context.CancelFunc
)

func startexp() error {
	Expctx, Expcanc = context.WithCancel(context.Background())
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("LogsExp panic: %v", r)
			}
		}()
		if err := logs.LogsExp(Expctx); err != nil {
			log.Printf("LogsExp error: %v", err)
		}
	}()
	return nil
}

func stopexp() {
	if Expcanc != nil {
		Expcanc()
	}
}

type ebpfrule struct {
	Id    uint64
	Sprt  uint16
	Dprt  uint16
	Prtcl uint8
	Wc    uint8
	_     [2]uint8 // C side the key size is 16 bytes
}

func Globalfb() error {

	var fb lpmv4
	fb.ipv4 = 0
	fb.pfxlen = 0

	if err := addlpm(false, true, 0, fb); err != nil {
		return err
	}
	if err := addlpm(false, false, 0, fb); err != nil {
		return err
	}
	return nil
}

func Rundae() error {

	conn, err := net.Dial("unix", skt)
	if err == nil {
		conn.Close()
		return nil
	}

	_ = os.Remove(skt)

	exe, errr := os.Executable()
	if errr != nil {
		return fmt.Errorf("error executing daemon: %v", errr)
	}

	cmd := exec.Command(exe, "dae")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Start()
	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		conn, err := net.Dial("unix", skt)
		if err == nil {
			conn.Close()
			return nil
		}
	}
	return fmt.Errorf("daemon failed to start.")
}

func Daeinit() error {

	if err := initdae(); err != nil {
		return fmt.Errorf("error initializing state: %v", err)
	}

	go func() {
		if err := ls(); err != nil {
			log.Printf("listener error: %v", err)
		}
	}()

	return nil

}

func ls() error {

	ln, err := net.Listen("unix", skt)
	if err != nil {
		return fmt.Errorf("listen on %s: %v", skt, err)
	}
	defer ln.Close()

	if err := os.Chmod(skt, 0660); err != nil {
		log.Printf("chmod socket: %v", err)
	}

	log.Printf("daemon listening on %s", skt)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go HCon(conn)
	}
}

func initdae() error {

	if _, err := os.Stat(state); os.IsNotExist(err) {
		if errr := os.MkdirAll(filepath.Dir(state), 0755); errr != nil {
			return errr
		}
		st := &State{
			NextID: 1,
			Src:    map[string]uint32{},
			Dst:    map[string]uint32{},
			Rules:  []Rule{},
		}
		if _, k := st.Src["0.0.0.0/0"]; !k { // global fallback
			st.Src["0.0.0.0/0"] = 0
		}
		if _, k := st.Dst["0.0.0.0/0"]; !k { // global fallback
			st.Dst["0.0.0.0/0"] = 0
		}
		out, _ := json.MarshalIndent(st, "", "  ")
		if err := os.WriteFile(state, out, 0o600); err != nil {
			return err
		}
		return nil
	}
	return nil

}

func HCon(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	l, err := r.ReadString('\n')
	if err != nil {
		return
	}

	l = strings.TrimSpace(l)
	parts := strings.Split(l, " ")

	switch parts[0] {
	case "src":
		if len(parts) == 3 {
			err := src(parts[1], parts[2])
			if err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "added")
			return
		} else {
			fmt.Fprintln(conn, "error unknown command")
			return
		}

	case "dst":
		if len(parts) == 3 {
			if err := dst(parts[1], parts[2]); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "added")
			return
		} else {
			fmt.Fprintln(conn, "error unknown command")
			return
		}

	case "rule":
		if len(parts) == 4 {
			if err := rule(parts[1], parts[2], parts[3]); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "added")
			return
		} else {
			fmt.Fprintln(conn, "error unknown command")
			return
		}

	case "log":

		if len(parts) == 2 {

			switch parts[1] {

			case "on":
				if err := logs.Logson(); err != nil {
					fmt.Fprintf(conn, "error %v\n", err)
					return
				}
				fmt.Fprintln(conn, "done")
				return

			case "off":
				if err := logs.Logsoff(); err != nil {
					fmt.Fprintf(conn, "error %v\n", err)
					return
				}
				fmt.Fprintln(conn, "done")
				return

			case "export":
				startexp()
				fmt.Fprintln(conn, "done")
				return

			case "stop":
				stopexp()
				fmt.Fprintln(conn, "done")
				return
			}

		} else {
			fmt.Fprintln(conn, "error unknown command")
			return
		}

	case "clear":

		switch parts[1] {

		case "src":

			if len(parts) == 4 {
				err := clrsrc(parts[2], parts[3])
				if err != nil {
					fmt.Fprintf(conn, "error %v\n", err)
					return
				}
				fmt.Fprintln(conn, "cleared")
				return
			} else {
				fmt.Fprintln(conn, "error unknown command")
				return
			}

		case "dst":

			if len(parts) == 4 {
				if err := clrdst(parts[2], parts[3]); err != nil {
					fmt.Fprintf(conn, "error %v\n", err)
					return
				}
				fmt.Fprintln(conn, "cleared")
				return
			} else {
				fmt.Fprintln(conn, "error unknown command")
				return
			}

		case "rule":

			if len(parts) == 5 {
				if err := clrrule(parts[2], parts[3], parts[4]); err != nil {
					fmt.Fprintf(conn, "error %v\n", err)
					return
				}
				fmt.Fprintln(conn, "cleared")
				return
			} else {
				fmt.Fprintln(conn, "error unknown command")
				return
			}

		default:
			fmt.Fprintln(conn, "error unknown command")
			return

		}

	default:
		fmt.Fprintln(conn, "error unknown command")
		return
	}
}

func regid(src []string, issrc bool) (id uint32, err error) {

	st, err := ldjs()
	if err != nil {
		return 0, err
	}

	var m map[string]uint32

	if issrc {
		m = st.Src
	} else {
		m = st.Dst
	}

	ksrc := src[0] + ("/" + src[1])
	if id, k := m[ksrc]; k {
		return id, nil
	}
	id = st.NextID
	st.NextID++
	m[ksrc] = id

	ip := net.ParseIP(src[0]).To4()
	if ip == nil {
		return 0, fmt.Errorf("bad ipv4: %s", src[0])
	}
	ipi := binary.BigEndian.Uint32(ip) // C side does ntohl except that it still compares with big endian so it has to be like this
	pfx, err := strconv.Atoi(src[1])
	if err != nil {
		return 0, err
	}

	var k lpmv4
	k.ipv4 = uint32(ipi)
	k.pfxlen = uint32(pfx)

	if issrc {
		st.Src[ksrc] = id
	} else {
		st.Dst[ksrc] = id
	}

	if err := addlpm(false, issrc, id, k); err != nil { // could error out before a rule is added later on and corrupt the state, too bad
		return 0, err
	}

	if err := svjs(st); err != nil {
		return 0, err
	}
	return id, nil

}

func src(src, prtcl string) error {
	if _, err := os.Stat(state); os.IsNotExist(err) {
		return fmt.Errorf("state doesn't exist")
	}

	prtcl, err := prtchk(prtcl)
	if err != nil {
		return err
	}

	s, err := prse(src)
	if err != nil {
		return err
	}
	if len(s) == 2 { // this only happens if i add ip:port rule syntax
		sr := []string{s[0], "32", s[1]}
		id, err := regid(sr, true) // on delete these have to stay, i don't like that but it'd be too complex to fix otherwise
		if err != nil {
			return err
		}
		ids := strconv.Itoa(int(id))
		if err := add(false, ids, s[1], "0", "0", prtcl); err != nil {
			return err
		}

	} else if len(s) == 3 {
		sr := []string{s[0], s[1], s[2]}
		id, err := regid(sr, true)
		if err != nil {
			return err
		}
		ids := strconv.Itoa(int(id))
		if err := add(false, ids, s[2], "0", "0", prtcl); err != nil {
			return err
		}
	}
	return nil
}

func dst(dst, prtcl string) error { // redundant
	if _, err := os.Stat(state); os.IsNotExist(err) {
		return fmt.Errorf("state doesn't exist")
	}

	prtcl, err := prtchk(prtcl)
	if err != nil {
		return err
	}

	s, err := prse(dst)
	if err != nil {
		return err
	}
	if len(s) == 2 {
		sr := []string{s[0], "32", s[1]}
		id, err := regid(sr, false)
		if err != nil {
			return err
		}
		ids := strconv.Itoa(int(id))
		if err := add(false, "0", "0", ids, s[1], prtcl); err != nil {
			return err
		}

	} else if len(s) == 3 {
		sr := []string{s[0], s[1], s[2]}
		id, err := regid(sr, false)
		if err != nil {
			return err
		}
		ids := strconv.Itoa(int(id))
		if err := add(false, "0", "0", ids, s[2], prtcl); err != nil {
			return err
		}
	}
	return nil
}

func rule(src, dst, prtcl string) error { // also redundant, i'll merge it later

	if _, err := os.Stat(state); os.IsNotExist(err) {
		return fmt.Errorf("state doesn't exist")
	}

	prtcl, err := prtchk(prtcl)
	if err != nil {
		return err
	}

	var sid string
	s, err := prse(src)
	if err != nil {
		return err
	}

	if len(s) == 2 {
		sr := []string{s[0], "32", s[1]}
		id, err := regid(sr, true)
		if err != nil {
			return err
		}
		sid = strconv.Itoa(int(id))

	} else if len(s) == 3 {
		sr := []string{s[0], s[1], s[2]}
		id, err := regid(sr, true)
		if err != nil {
			return err
		}
		sid = strconv.Itoa(int(id))
	}

	var did string
	d, err := prse(dst)
	if err != nil {
		return err
	}

	if len(d) == 2 {
		dr := []string{d[0], "32", d[1]}
		id, err := regid(dr, false)
		if err != nil {
			return err
		}
		did = strconv.Itoa(int(id))

	} else if len(d) == 3 {
		dr := []string{d[0], d[1], d[2]}
		id, err := regid(dr, false)
		if err != nil {
			return err
		}
		did = strconv.Itoa(int(id))
	}

	sprt := s[len(s)-1]
	dprt := d[len(d)-1]

	if err := add(false, sid, sprt, did, dprt, prtcl); err != nil {
		return err
	}
	return nil

}

func prtchk(prtcl string) (string, error) {
	switch prtcl {
	case "TCP":
		prtcl = "6"
		return prtcl, nil
	case "tcp":
		prtcl = "6"
		return prtcl, nil
	case "UDP":
		prtcl = "17"
		return prtcl, nil
	case "udp":
		prtcl = "17"
		return prtcl, nil
	case "ANY":
		prtcl = "0"
		return prtcl, nil
	case "any":
		prtcl = "0"
		return prtcl, nil
	case "0":
		return prtcl, nil

	default:
		return "", fmt.Errorf("invalid prtcl: %s", prtcl)
	}

}

func add(rem bool, srcid, sprt, dstid, dprt, prtcl string) error {

	st, err := ldjs()
	if err != nil {
		return err
	}

	wc := wchlp(sprt, dprt, prtcl)
	if wc == "" {
		return fmt.Errorf("wc is empty.")
	}
	srcidi, _ := strconv.Atoi(srcid)
	dstidi, _ := strconv.Atoi(dstid)
	prtcli, _ := strconv.Atoi(prtcl)
	sprti, _ := strconv.Atoi(sprt)
	dprti, _ := strconv.Atoi(dprt)
	wci, _ := strconv.Atoi(wc)

	if !rem {
		st.Rules = append(st.Rules, Rule{
			SrcID: uint32(srcidi),
			DstID: uint32(dstidi),
			Sprt:  uint16(sprti),
			Dprt:  uint16(dprti),
			Prtcl: uint8(prtcli),
			Wc:    uint8(wci),
		})

		if err := addrule(false, uint32(srcidi), uint32(dstidi), uint16(sprti), uint16(dprti), uint8(prtcli), uint8(wci)); err != nil {
			return err
		}
	} else if rem {

		rle := Rule{
			SrcID: uint32(srcidi),
			DstID: uint32(dstidi),
			Sprt:  uint16(sprti),
			Dprt:  uint16(dprti),
			Prtcl: uint8(prtcli),
			Wc:    uint8(wci),
		}

		st.Rules = slices.DeleteFunc(st.Rules, func(r Rule) bool {
			return r == rle
		})

		if err := addrule(true, uint32(srcidi), uint32(dstidi), uint16(sprti), uint16(dprti), uint8(prtcli), uint8(wci)); err != nil {
			return err
		}
	}

	if err := svjs(st); err != nil {
		return err
	}

	return nil

}

func wchlp(sprt, dprt, prtcl string) (wc string) {
	var wcc string

	if sprt != "0" && dprt != "0" && prtcl != "0" {
		wcc = "0"
	}
	if sprt != "0" && dprt != "0" && prtcl == "0" {
		wcc = "1"
	}
	if sprt == "0" && dprt != "0" && prtcl != "0" {
		wcc = "2"
	}
	if sprt == "0" && dprt != "0" && prtcl == "0" {
		wcc = "3"
	}
	if sprt != "0" && dprt == "0" && prtcl != "0" {
		wcc = "4"
	}
	if sprt != "0" && dprt == "0" && prtcl == "0" {
		wcc = "5"
	}
	if sprt == "0" && dprt == "0" && prtcl != "0" {
		wcc = "6"
	}
	if sprt == "0" && dprt == "0" && prtcl == "0" {
		wcc = "7"
	}
	return wcc

}

func prse(s string) ([]string, error) { // no hostname res but that's for the reconciler
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty input")
	}

	i := strings.LastIndex(s, ":")
	if i < 0 {
		return nil, fmt.Errorf("missing :port in %q", s)
	}
	host := strings.TrimSpace(s[:i])
	portStr := strings.TrimSpace(s[i+1:])
	if host == "" || portStr == "" {
		return nil, fmt.Errorf("bad host/port in %q", s)
	}

	p, err := strconv.Atoi(portStr)
	if err != nil || p < 0 || p > 65535 {
		return nil, fmt.Errorf("bad port %q", portStr)
	}

	if j := strings.LastIndex(host, "/"); j >= 0 {
		ipStr := strings.TrimSpace(host[:j])
		cidrStr := strings.TrimSpace(host[j+1:])
		if ipStr == "" || cidrStr == "" {
			return nil, fmt.Errorf("bad ip/cidr in %q", s)
		}
		if net.ParseIP(ipStr).To4() == nil {
			return nil, fmt.Errorf("bad ipv4 %q", ipStr)
		}
		c, err := strconv.Atoi(cidrStr)
		if err != nil || c < 0 || c > 32 {
			return nil, fmt.Errorf("bad cidr %q", cidrStr)
		}
		return []string{ipStr, cidrStr, strconv.Itoa(p)}, nil
	}

	if net.ParseIP(host).To4() == nil {
		return nil, fmt.Errorf("bad ipv4 %q", host)
	}
	return []string{host, strconv.Itoa(p)}, nil
}

func ldjs() (*State, error) {

	s, err := os.ReadFile(state)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("state doesn't exist")
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(s, &st); err != nil {
		return nil, err
	}
	return &st, nil

}

func svjs(st *State) error {

	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(state, b, 0o600); err != nil {
		return err
	}
	return nil

}

func addlpm(rem, issrc bool, id uint32, lpm lpmv4) error {

	if issrc {

		m, err := ebpf.LoadPinnedMap(srcpth, nil)
		if err != nil {
			return fmt.Errorf("error opening map %s: %w", srcpth, err)
		}
		defer m.Close()
		if !rem {
			if err := m.Put(lpm, id); err != nil {
				return err
			}
		} else if rem {
			if err := m.Delete(lpm); err != nil {
				return err
			}
		}
		return nil

	} else {

		m, err := ebpf.LoadPinnedMap(dstpth, nil)
		if err != nil {
			return fmt.Errorf("error opening map %s: %w", dstpth, err)
		}
		defer m.Close()
		if !rem {
			if err := m.Put(lpm, id); err != nil {
				return err
			}
		} else if rem {
			if err := m.Delete(lpm); err != nil {
				return err
			}
		}
		return nil
	}

}

func addrule(rem bool, srcid, dstid uint32, sprt, dprt uint16, prtcl, wc uint8) error {

	var k ebpfrule

	fid := (uint64(srcid) << 32) | uint64(dstid)

	k.Id = fid
	k.Prtcl = prtcl
	k.Sprt = sprt
	k.Dprt = dprt
	k.Wc = wc

	m, err := ebpf.LoadPinnedMap(rlespth, nil)
	if err != nil {
		return fmt.Errorf("error opening map %s: %w", rlespth, err)
	}
	defer m.Close()
	if !rem {
		if err := m.Put(k, uint8(1)); err != nil {
			return err
		}
	} else if rem {
		if err := m.Delete(k); err != nil {
			return err
		}
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// CLEAR

func lkupid(issrc bool, srcdst string) (string, error) {

	st, err := ldjs()
	if err != nil {
		return "", err
	}

	if issrc {
		id, k := st.Src[srcdst]
		if !k {
			return "", fmt.Errorf("can't find src/dst id, either gone or wrong.")
		}
		idi := strconv.Itoa(int(id))
		return idi, nil
	} else {
		id, k := st.Dst[srcdst]
		if !k {
			return "", fmt.Errorf("can't find src/dst id, either gone or wrong.")
		}
		idi := strconv.Itoa(int(id))
		return idi, nil
	}

}
func clrsrc(src, prtcl string) error {
	if _, err := os.Stat(state); os.IsNotExist(err) {
		return fmt.Errorf("state doesn't exist")
	}

	prtcl, err := prtchk(prtcl)
	if err != nil {
		return err
	}

	s, err := prse(src)
	if err != nil {
		return err
	}
	if len(s) == 2 {
		sr := s[0] + "/32"
		ids, err := lkupid(true, sr)
		if err != nil {
			return err
		}
		if err := add(true, ids, s[1], "0", "0", prtcl); err != nil {
			return err
		}

	} else if len(s) == 3 {
		sr := s[0] + ("/" + s[1])
		ids, err := lkupid(true, sr)
		if err != nil {
			return err
		}
		if err := add(true, ids, s[2], "0", "0", prtcl); err != nil {
			return err
		}
	}
	return nil
}

func clrdst(dst, prtcl string) error {
	if _, err := os.Stat(state); os.IsNotExist(err) {
		return fmt.Errorf("state doesn't exist")
	}

	prtcl, err := prtchk(prtcl)
	if err != nil {
		return err
	}

	s, err := prse(dst)
	if err != nil {
		return err
	}
	if len(s) == 2 {
		sr := s[0] + "/32"
		ids, err := lkupid(false, sr)
		if err != nil {
			return err
		}
		if err := add(true, "0", "0", ids, s[1], prtcl); err != nil {
			return err
		}

	} else if len(s) == 3 {
		sr := s[0] + ("/" + s[1])
		ids, err := lkupid(false, sr)
		if err != nil {
			return err
		}
		if err := add(true, "0", "0", ids, s[2], prtcl); err != nil {
			return err
		}
	}
	return nil
}

func clrrule(src, dst, prtcl string) error {

	if _, err := os.Stat(state); os.IsNotExist(err) {
		return fmt.Errorf("state doesn't exist")
	}

	prtcl, err := prtchk(prtcl)
	if err != nil {
		return err
	}

	var sid string
	s, err := prse(src)
	if err != nil {
		return err
	}

	if len(s) == 2 {
		sr := s[0] + "/32"
		sid, err = lkupid(true, sr)
		if err != nil {
			return err
		}

	} else if len(s) == 3 {
		sr := s[0] + ("/" + s[1])
		sid, err = lkupid(true, sr)
		if err != nil {
			return err
		}

	}

	var did string
	d, err := prse(dst)
	if err != nil {
		return err
	}

	if len(d) == 2 {
		dr := d[0] + "/32"
		did, err = lkupid(false, dr)
		if err != nil {
			return err
		}

	} else if len(d) == 3 {
		dr := d[0] + ("/" + d[1])
		did, err = lkupid(false, dr)
		if err != nil {
			return err
		}
	}

	if err := add(true, sid, s[1], did, d[1], prtcl); err != nil {
		return err
	}
	return nil

}
