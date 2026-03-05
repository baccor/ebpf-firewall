package logs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"bytes"
	"encoding/binary"
	"encoding/json"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const islogspth = "/sys/fs/bpf/fw_islogs"
const logspth = "/sys/fs/bpf/fw_logs"
const logsjs = "/var/tmp/frwll/logs.json"

type logev struct {
	Fid   uint64
	Srcip uint32
	Dstip uint32
	Sprt  uint16
	Dprt  uint16
	Prtcl uint8
	Act   uint8
}

type logjson struct {
	Fid   uint64 `json:"fid"`
	Srcip string `json:"src_ip"`
	Dstip string `json:"dst_ip"`
	Sprt  uint16 `json:"src_port"`
	Dprt  uint16 `json:"dst_port"`
	Prtcl string `json:"protocol"`
	Act   string `json:"action"`
}

func ismap() error {

	if _, err := os.Stat(islogspth); os.IsNotExist(err) {
		return fmt.Errorf("islogs map doesn't exist")
	}

	if _, err := os.Stat(logspth); os.IsNotExist(err) {
		return fmt.Errorf("logs map doesn't exist")
	}
	return nil
}

func islogjs() error {
	if _, err := os.Stat(logsjs); os.IsNotExist(err) {
		empty, err := json.Marshal([]logjson{})
		if err != nil {
			return fmt.Errorf("error marshaling empty events: %w", err)
		}
		if err := os.WriteFile(logsjs, empty, 0644); err != nil {
			return fmt.Errorf("logs.json doesn't exist, error creating: %w", err)
		}
	}
	return nil
}

func jsconv(l logev) logjson {
	proto := ""
	if l.Prtcl == 6 {
		proto = "TCP"
	} else if l.Prtcl == 17 {
		proto = "UDP"
	}

	act := "DROPPED"
	if l.Act == 0 {
		act = "ALLOWED"
	}

	ipstr := func(n uint32) string {
		return fmt.Sprintf("%d.%d.%d.%d", n>>24, (n>>16)&0xff, (n>>8)&0xff, n&0xff)
	}

	return logjson{
		Fid:   l.Fid,
		Srcip: ipstr(l.Srcip),
		Dstip: ipstr(l.Dstip),
		Sprt:  l.Sprt,
		Dprt:  l.Dprt,
		Prtcl: proto,
		Act:   act,
	}
}

func Logson() error {

	k := uint8(1)

	if err := ismap(); err != nil {
		return err
	}

	m, err := ebpf.LoadPinnedMap(islogspth, nil)
	if err != nil {
		return fmt.Errorf("error opening map %s: %w", islogspth, err)
	}
	if err := m.Update(k, uint8(1), 0); err != nil {
		return fmt.Errorf("error updating logson map: %w", err)
	}

	return nil
}

func Logsoff() error {

	k := uint8(1)

	if err := ismap(); err != nil {
		return err
	}

	m, err := ebpf.LoadPinnedMap(islogspth, nil)
	if err != nil {
		return fmt.Errorf("error opening map %s: %w", islogspth, err)
	}
	if err := m.Update(k, uint8(0), 0); err != nil {
		return fmt.Errorf("error updating logson map: %w", err)
	}

	return nil
}

const maxlogs = 100

func writeLog(log logev) error {
	var events []logjson

	logjs := jsconv(log)

	data, err := os.ReadFile(logsjs)
	if err == nil {
		json.Unmarshal(data, &events)
	}

	events = append(events, logjs)
	if len(events) > maxlogs {
		events = events[len(events)-maxlogs:]
	}

	out, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(logsjs, out, 0644)
}

func LogsExp(ctx context.Context) error {

	log.Println("LogsExp starting")
	if err := ismap(); err != nil {
		log.Printf("ismap failed: %v", err)
		return err
	}
	if err := islogjs(); err != nil {
		log.Printf("islogjs failed: %v", err)
		return err
	}

	m, err := ebpf.LoadPinnedMap(logspth, nil)
	if err != nil {
		return fmt.Errorf("error opening map %s: %w", logspth, err)
	}

	rb, err := ringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("error creating ringbuf reader: %w", err)
	}

	var loge logev

	go func() {
		<-ctx.Done()
		rb.Close()
	}()

	for {

		logs, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}

		if err := binary.Read(bytes.NewReader(logs.RawSample), binary.LittleEndian, &loge); err != nil { // should be little endian already
			log.Printf("error reading log: %v", err)
			continue

		}

		if err := writeLog(loge); err != nil {
			return fmt.Errorf("error writing log: %w", err)
		}

	}

}
