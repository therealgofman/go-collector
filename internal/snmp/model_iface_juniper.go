package snmp

import (
	"regexp"
	"strconv"
	"strings"
)

// -------------------------------- Juniper (интерфейсы / VLAN) --------------------------
// -------------------------------- aka get_juniper_ports --------------------------------

var juniperQBridgeStaticInterfaceOIDs = map[string]string{
	"ifAdminStatus":              "1.3.6.1.2.1.2.2.1.7",
	"ifType":                     "1.3.6.1.2.1.2.2.1.3",
	"ifName":                     "1.3.6.1.2.1.31.1.1.1.1",
	"ifAlias":                    "1.3.6.1.2.1.31.1.1.1.18",
	"dot1qVlanStaticEgressPorts": "1.3.6.1.2.1.17.7.1.4.3.1.2",
	"dot1dBasePortIfIndex":       "1.3.6.1.2.1.17.1.4.1.2",
}

var juniperSubifNameRe = regexp.MustCompile(`^(et-\d+/\d+/\d+|xe-\d+/\d+/\d+|ge-\d+/\d+/\d+|ae\d+|em\d+|fxp\d+)\.(\d+)$`)
var juniperPortListRe = regexp.MustCompile(`^\s*\d+(?:\s*,\s*\d+)*\s*$`)

func parseJuniperBridgePortList(raw string) []int {
	if !juniperPortListRe.MatchString(raw) {
		return nil
	}
	out := make([]int, 0, 8)
	for _, token := range strings.Split(raw, ",") {
		bp, err := strconv.Atoi(strings.TrimSpace(token))
		if err != nil || bp <= 0 {
			continue
		}
		out = append(out, bp)
	}
	return out
}

func applyJuniperStaticEgressVLANs(
	ports InterfacePorts,
	ifiIdxVLAN map[string]map[int]struct{},
) {
	for ifidx, p := range ports {
		vlans, ok := ifiIdxVLAN[ifidx]
		if !ok {
			continue
		}
		for vid := range vlans {
			p.VLANs[vid] = 1
			p.Tagged = true
		}
		ports[ifidx] = p
	}
}

// juniperIfaceQBridgeStatic — Juniper: VLAN из subinterface-имён и из Q-BRIDGE static egress.
type juniperIfaceQBridgeStatic struct{}

// NewJuniperIfaceQBridgeStatic возвращает стратегию сбора интерфейсов для Juniper.
func NewJuniperIfaceQBridgeStatic() VendorIfaceCollector {
	return &juniperIfaceQBridgeStatic{}
}

// CollectInterfaces для Juniper: VLAN из имён вида ge-0/0/1.123 + static egress (список bridge-port'ов).
func (*juniperIfaceQBridgeStatic) CollectInterfaces(c *Client) (InterfacePorts, error) {
	w, err := walkMany(c, juniperQBridgeStaticInterfaceOIDs, "")
	if err != nil {
		return nil, err
	}
	ports := InterfacePorts{}
	for ifidx, name := range w["ifName"] {
		name = strings.TrimSpace(strings.ReplaceAll(name, " interface ", ""))
		name = strings.ReplaceAll(name, " ", "_")
		n, _ := strconv.Atoi(ifidx)
		p := InterfacePort{
			VLANs:   map[int]int{},
			Name:    name,
			Descr:   w["ifAlias"][ifidx],
			IfIndex: n,
		}
		if strings.TrimSpace(w["ifAdminStatus"][ifidx]) != "1" {
			p.Disabled = true
		}
		ports[ifidx] = p
	}

	nameToIfIndex := map[string]string{}
	for ifidx, p := range ports {
		nameToIfIndex[p.Name] = ifidx
	}

	dropSubinterfaces := map[string]struct{}{}
	for ifidx, p := range ports {
		name := p.Name
		if mm := juniperSubifNameRe.FindStringSubmatch(name); len(mm) == 3 {
			base, vlanS := mm[1], mm[2]
			vid, err := strconv.Atoi(vlanS)
			if err == nil && vid > 0 {
				if baseIfidx, ok := nameToIfIndex[base]; ok {
					base := ports[baseIfidx]
					base.VLANs[vid] = 1
					base.Tagged = true
					ports[baseIfidx] = base
				}
			}
			dropSubinterfaces[ifidx] = struct{}{}
			continue
		}
		if strings.HasSuffix(name, ".0") {
			dropSubinterfaces[ifidx] = struct{}{}
		}
	}

	vlanSuffixRe := regexp.MustCompile(`(\d+)$`)
	ifiIdxVLAN := map[string]map[int]struct{}{}
	for suffix, raw := range w["dot1qVlanStaticEgressPorts"] {
		mm := vlanSuffixRe.FindStringSubmatch(strings.TrimSpace(suffix))
		if len(mm) != 2 {
			continue
		}
		vid, err := strconv.Atoi(mm[1])
		if err != nil || vid <= 0 {
			continue
		}
		for _, bp := range parseJuniperBridgePortList(raw) {
			ifidx, ok := w["dot1dBasePortIfIndex"][strconv.Itoa(bp)]
			if !ok {
				continue
			}
			if _, ok := ifiIdxVLAN[ifidx]; !ok {
				ifiIdxVLAN[ifidx] = map[int]struct{}{}
			}
			ifiIdxVLAN[ifidx][vid] = struct{}{}
		}
	}

	for ifidx := range dropSubinterfaces {
		delete(ports, ifidx)
	}
	for key, p := range ports {
		delete(p.VLANs, 0)
		ports[key] = p
	}
	applyJuniperStaticEgressVLANs(ports, ifiIdxVLAN)

	out := InterfacePorts{}
	for ifidx, p := range ports {
		out[ifidx] = p
	}
	return out, nil
}
