package snmp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Контракт результата: map[ifIndex строка] → {name, descr, ifindex, vlan map, опционально tag, disab}.

// -------------------------------- Cisco L2 (интерфейсы / VLAN) --------------------------------
// -------------------------------- aka get_cisco_snmp_tab_vlan2 --------------------------------
var ciscoL2InterfaceOIDs = map[string]string{
	"ifAdminStatus":   "1.3.6.1.2.1.2.2.1.7",
	"ifName":          "1.3.6.1.2.1.31.1.1.1.1",
	"ifAlias":         "1.3.6.1.2.1.31.1.1.1.18",
	"ifType":          "1.3.6.1.2.1.2.2.1.3",
	"ifXconnectPorts": "1.3.6.1.4.1.9.10.106.1.2.1.21",
	"untaggedPorts":   "1.3.6.1.4.1.9.9.68.1.2.1.1.2",
	"encapsulation":   "1.3.6.1.4.1.9.9.46.1.6.1.1.16",
	"tag1":            "1.3.6.1.4.1.9.9.46.1.6.1.1.4",
	"tag2":            "1.3.6.1.4.1.9.9.46.1.6.1.1.17",
	"tag3":            "1.3.6.1.4.1.9.9.46.1.6.1.1.18",
	"tag4":            "1.3.6.1.4.1.9.9.46.1.6.1.1.19",
}

// ciscoIfaceL2 — VendorIfaceCollector: Cisco L2 (untagged через community@VLAN, trunk tag1..4, ifXconnectPorts).
type ciscoIfaceL2 struct{}

// NewCiscoIfaceL2 возвращает стратегию сбора интерфейсов для Cisco Catalyst L2 (ciscoL2InterfaceOIDs).
func NewCiscoIfaceL2() VendorIfaceCollector {
	return &ciscoIfaceL2{}
}

// CollectInterfaces для Cisco: untagged VLAN через community@VLAN + dot1dBasePortIfIndex, trunk через tag1..tag4 bitmap,
// дополнение VLAN из ifXconnectPorts; фильтр портов без VLAN кроме ifType 6.
func (*ciscoIfaceL2) CollectInterfaces(c *Client) (map[string]any, error) {
	w, err := walkMany(c, ciscoL2InterfaceOIDs, "")
	if err != nil {
		return nil, err
	}
	ifxconMap := parseCiscoXConnect(w["ifXconnectPorts"])
	ports := map[string]map[string]any{}
	for ifidx, typ := range w["ifType"] {
		n, _ := strconv.Atoi(ifidx)
		port := map[string]any{
			"vlan":    map[int]int{},
			"name":    w["ifName"][ifidx],
			"descr":   w["ifAlias"][ifidx],
			"ifindex": n,
			"_typ":    typ,
		}
		if w["ifAdminStatus"][ifidx] == "2" {
			port["disab"] = 1
		}
		ports[ifidx] = port
	}
	vlans := []int{}
	untagged := map[string]struct{}{}
	for suffix, raw := range w["untaggedPorts"] {
		re := regexp.MustCompile(`(\d+)$`)
		mm := re.FindStringSubmatch(strings.TrimSpace(suffix))
		if len(mm) != 2 {
			continue
		}
		v, _ := strconv.Atoi(mm[1])
		comm := fmt.Sprintf("%s@%d", c.Community, v)
		dbp, err := c.Walk("1.3.6.1.2.1.17.1.4.1.2", comm)
		if err != nil {
			continue
		}
		mask := bitmaskToArray(raw)
		for dot1d, ifidx := range dbp {
			pos, _ := strconv.Atoi(dot1d)
			if pos < 1 || pos > len(mask) || mask[pos-1] != "1" {
				continue
			}
			p, ok := ports[ifidx]
			if !ok {
				continue
			}
			p["vlan"].(map[int]int)[v] = 1
			untagged[ifidx] = struct{}{}
		}
		vlans = append(vlans, v)
	}
	for ifidx, p := range ports {
		if _, ok := untagged[ifidx]; ok {
			continue
		}
		enc := w["encapsulation"][ifidx]
		if enc != "" && enc != "4" {
			continue
		}
		for _, vlanNum := range vlans {
			pos := vlanNum
			var arr []string
			switch {
			case vlanNum < 1024:
				arr = bitmaskToArray(w["tag1"][ifidx])
			case vlanNum < 2048:
				arr = bitmaskToArray(w["tag2"][ifidx])
				pos = vlanNum - 1024
			case vlanNum < 3072:
				arr = bitmaskToArray(w["tag3"][ifidx])
				pos = vlanNum - 2048
			default:
				arr = bitmaskToArray(w["tag4"][ifidx])
				pos = vlanNum - 3072
			}
			if pos >= 0 && pos < len(arr) && arr[pos] == "1" {
				p["tag"] = 1
				p["vlan"].(map[int]int)[vlanNum] = 1
			}
		}
	}
	out := map[string]any{}
	for ifidx, p := range ports {
		if len(p["vlan"].(map[int]int)) == 0 && fmt.Sprint(p["_typ"]) != "6" {
			continue
		}
		name := fmt.Sprint(p["name"])
		for _, key := range []string{name, shortPortName(name)} {
			if key == "" {
				continue
			}
			if extra, ok := ifxconMap[key]; ok {
				for _, xvl := range extra {
					p["vlan"].(map[int]int)[xvl] = 1
				}
				break
			}
		}
		delete(p, "_typ")
		out[ifidx] = p
	}
	return out, nil
}

// -------------------------------- Cisco L3 (VLAN интерфейсы) --------------------------------
// -------------------------------- aka get_cisco_snmp_tab_vlan3 ------------------------------
var ciscoL3InterfaceOIDs = map[string]string{
	"ifName":  "1.3.6.1.2.1.31.1.1.1.1",
	"ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
	"routedV": "1.3.6.1.4.1.9.9.128.1.1.1.1.3",
}

// ciscoIfaceL3 — VendorIfaceCollector: L3 VLAN интерфейсы Cisco через CISCO-VLAN-IFTABLE-RELATIONSHIP-MIB.
type ciscoIfaceL3 struct{}

// NewCiscoIfaceL3 возвращает стратегию сбора L3 VLAN-интерфейсов Cisco.
func NewCiscoIfaceL3() VendorIfaceCollector {
	return &ciscoIfaceL3{}
}

// CollectInterfaces для Cisco L3: берёт пары vlan.ifIndex из routedV и агрегирует VLAN по имени интерфейса.
func (*ciscoIfaceL3) CollectInterfaces(c *Client) (map[string]any, error) {
	w, err := walkMany(c, ciscoL3InterfaceOIDs, "")
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`^(\d+)\.(\d+)$`)
	out := map[string]any{}
	for oidSuffix := range w["routedV"] {
		mm := re.FindStringSubmatch(strings.TrimSpace(oidSuffix))
		if len(mm) != 3 {
			continue
		}
		vlan, err := strconv.Atoi(mm[1])
		if err != nil {
			continue
		}
		ifidx := mm[2]
		ifName, ok := w["ifName"][ifidx]
		if !ok || ifName == "" {
			continue
		}
		p, ok := out[ifName]
		if !ok {
			n, _ := strconv.Atoi(ifidx)
			p = map[string]any{
				"vlan":    map[int]int{},
				"name":    ifName,
				"descr":   w["ifAlias"][ifidx],
				"tag":     1,
				"ifindex": n,
			}
			out[ifName] = p
		}
		p.(map[string]any)["vlan"].(map[int]int)[vlan] = 1
	}
	return out, nil
}
