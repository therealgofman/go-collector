package snmp

import (
	"regexp"
	"strings"
)

// juniperIfNameVLANPatterns — VLAN из ifName на Junos (ARP привязан к L3 ifIndex, не к dot1qVlanStaticName).
var juniperIfNameVLANPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^irb\.(\d+)$`),
	regexp.MustCompile(`^(?:xe|ge|et)-\d+/\d+/\d+\.(\d+)$`),
	regexp.MustCompile(`^(?:ae|em|fxp)\d+\.(\d+)$`),
}

// ifindexToVLANJuniper строит ifIndex → номер VLAN по суффиксу unit в ifName (xe-0/1/2.1000 → 1000, irb.664 → 664).
func ifindexToVLANJuniper(ifName map[string]string) map[string]string {
	iv := map[string]string{}
	for ifidx, name := range ifName {
		name = strings.TrimSpace(name)
		for _, re := range juniperIfNameVLANPatterns {
			if mm := re.FindStringSubmatch(name); len(mm) == 2 && mm[1] != "0" {
				iv[ifidx] = mm[1]
				break
			}
		}
	}
	return iv
}

var juniperARPOIDs = map[string]string{
	"ifName": "1.3.6.1.2.1.31.1.1.1.1",
	"vsn":    "1.3.6.1.2.1.17.7.1.4.3.1.1",
	"arp":    "1.3.6.1.2.1.4.22.1.2",
}

// juniperARP — VendorARPCollector: ARP на Juniper; VLAN из ifName, при необходимости дополняется точным Q-BRIDGE staticName==ifName.
type juniperARP struct{}

// NewJuniperARP возвращает стратегию ARP для Juniper MX/Junos.
func NewJuniperARP() VendorARPCollector {
	return &juniperARP{}
}

// CollectARP (Juniper): ifName + ipNetToMediaPhysAddress; VLAN из unit в имени интерфейса; merge с Q-BRIDGE при совпадении имён.
// Таблицу ARP обходим BulkWalk (GETBULK); ifName и dot1qVlanStaticName — Walk (GETNEXT).
func (*juniperARP) CollectARP(c *Client) (map[string]map[string]string, error) {
	ifn, err := c.WalkWithOptions(juniperARPOIDs["ifName"], "", nil)
	if err != nil {
		return nil, err
	}
	vsn, err := c.WalkWithOptions(juniperARPOIDs["vsn"], "", nil)
	if err != nil {
		return nil, err
	}
	arpWalkUsesGetBulk := true
	arp, err := c.WalkWithOptions(juniperARPOIDs["arp"], "", &arpWalkUsesGetBulk)
	if err != nil {
		return nil, err
	}
	iv := ifindexToVLANJuniper(ifn)
	for ifidx, v := range ifindexToVLANQBridge(ifn, vsn) {
		if _, ok := iv[ifidx]; !ok {
			iv[ifidx] = v
		}
	}
	return joinARPToVLAN(arp, iv), nil
}
