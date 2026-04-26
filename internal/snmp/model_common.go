package snmp

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// bitmaskToArrayWithBEF разворачивает октетную строку SNMP в массив "0"/"1"
//
//	bef false → unpack "B*" (старший бит октета первым — Q-BRIDGE/Cisco по умолчанию);
//	bef true  → unpack "b*" (младший бит октета первым).
func bitmaskToArrayWithBEF(s string, bef bool) []string {
	b := []byte(s)
	out := make([]string, 0, len(b)*8)
	for _, x := range b {
		if bef {
			for i := 0; i < 8; i++ {
				if (x & (1 << i)) != 0 {
					out = append(out, "1")
				} else {
					out = append(out, "0")
				}
			}
			continue
		}
		for i := 7; i >= 0; i-- {
			if (x & (1 << i)) != 0 {
				out = append(out, "1")
			} else {
				out = append(out, "0")
			}
		}
	}
	return out
}

func bitmaskToArray(s string) []string {
	return bitmaskToArrayWithBEF(s, false)
}

// shortPortName сокращает длинные префиксы имён портов Cisco (FastEthernet→Fa и т.д.) для сопоставления с xconnect.
func shortPortName(name string) string {
	s := name
	s = regexp.MustCompile(`^FastEthernet`).ReplaceAllString(s, "Fa")
	s = regexp.MustCompile(`^TenGigabitEthernet`).ReplaceAllString(s, "Te")
	s = regexp.MustCompile(`^GigabitEthernet`).ReplaceAllString(s, "Gi")
	s = regexp.MustCompile(`^Port-channel`).ReplaceAllString(s, "Po")
	return s
}

// parseCiscoXConnect разбирает значения ifXconnectPorts (строки вида "....vlan") в карту короткое_имя_порта → список VLAN.
func parseCiscoXConnect(ifxcon map[string]string) map[string][]int {
	out := map[string][]int{}
	for _, val := range ifxcon {
		s := strings.TrimSpace(val)
		if s == "" || !strings.Contains(s, ".") {
			continue
		}
		parts := strings.Split(s, ".")
		if len(parts) < 2 {
			continue
		}
		vlanS := parts[len(parts)-1]
		vlan, err := strconv.Atoi(vlanS)
		if err != nil {
			continue
		}
		port := strings.Join(parts[:len(parts)-1], ".")
		ps := shortPortName(port)
		if strings.HasPrefix(ps, "Fa") || strings.HasPrefix(ps, "Te") || strings.HasPrefix(ps, "Gi") || strings.HasPrefix(ps, "Po") {
			out[ps] = append(out[ps], vlan)
		}
	}
	return out
}

// walkMany — именованный набор OID (логический ключ → OID) только через Walk (GETNEXT), порядок ключей стабильный.
func walkMany(c *Client, oids map[string]string, community string) (map[string]map[string]string, error) {
	return walkNamedOIDs(c, oids, community, nil)
}

// walkNamedOIDs вызывает WalkManyOIDs либо параллельные одиночные обходы при GO_COLLECTOR_SNMP_OID_PARALLELISM>1
// (расширение для тяжёлых агентов; при parallelism=1 — одна сессия, последовательные OID).
func walkNamedOIDs(c *Client, oids map[string]string, community string, useBulkWalk *bool) (map[string]map[string]string, error) {
	keys := make([]string, 0, len(oids))
	oidList := make([]string, 0, len(oids))
	for k := range oids {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		oidList = append(oidList, oids[k])
	}

	parallelism := 1
	if v := strings.TrimSpace(os.Getenv("GO_COLLECTOR_SNMP_OID_PARALLELISM")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 1 {
			parallelism = n
		}
	}

	byOID := map[string]map[string]string{}
	if parallelism <= 1 || len(oidList) <= 1 {
		var err error
		byOID, err = c.WalkManyOIDs(oidList, community, useBulkWalk)
		if err != nil {
			return nil, err
		}
	} else {
		// Параллельный режим открывает независимые walk’ы на каждый OID.
		// Полезен для быстрых/надёжных агентов, но может перегружать слабые устройства.
		type item struct {
			oid string
			t   map[string]string
			err error
		}
		sem := make(chan struct{}, parallelism)
		ch := make(chan item, len(oidList))
		var wg sync.WaitGroup
		for _, oid := range oidList {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				// Для параллельной ветки тот же режим GETNEXT/GETBULK, что и при последовательном WalkManyOIDs.
				one, err := c.WalkManyOIDs([]string{oid}, community, useBulkWalk)
				<-sem
				if err != nil {
					ch <- item{oid: oid, t: nil, err: err}
					return
				}
				ch <- item{oid: oid, t: one[oid], err: nil}
			}()
		}
		wg.Wait()
		close(ch)
		for it := range ch {
			if it.err != nil {
				return nil, it.err
			}
			byOID[it.oid] = it.t
		}
	}

	out := map[string]map[string]string{}
	for _, k := range keys {
		t, ok := byOID[oids[k]]
		if !ok {
			return nil, fmt.Errorf("walk result missing oid %s", oids[k])
		}
		out[k] = t
	}
	return out, nil
}
