package snmp

import (
	"regexp"
	"strconv"
	"strings"
)

// ciscoARPVlanIf — VendorARPCollector: ARP для Cisco, VLAN из имён интерфейсов VlanNNN.
type ciscoARPVlanIf struct{}
type ciscoARPL3Router struct{}

// NewCiscoVlanARP возвращает стратегию ARP для Cisco (ifDescr + ipNetToMediaPhysAddress).
func NewCiscoVlanARP() VendorARPCollector {
	return &ciscoARPVlanIf{}
}

// NewCiscoL3RouterARP возвращает ARP-стратегию Cisco L3 router (cviRoutedVlanIfIndex + ipNetToMedia + mplsVpnInterfaceConfRowStatus).
func NewCiscoL3RouterARP() VendorARPCollector {
	return &ciscoARPL3Router{}
}

// CollectARP (Cisco): ifDescr, ARP table, VLAN из имён Vlan*.
func (*ciscoARPVlanIf) CollectARP(c *Client) (map[string]map[string]string, error) {
	ifd, err := c.Walk("1.3.6.1.2.1.2.2.1.2", "")
	if err != nil {
		return nil, err
	}
	arp, err := c.Walk("1.3.6.1.2.1.4.22.1.2", "")
	if err != nil {
		return nil, err
	}
	iv := map[string]string{}
	re := regexp.MustCompile(`(?i)Vlan.*?(\d+)`)
	for ifidx, name := range ifd {
		mm := re.FindStringSubmatch(name)
		if len(mm) == 2 {
			iv[ifidx] = mm[1]
		}
	}
	return joinARPToVLAN(arp, iv), nil
}

func decodeCiscoVRFNameFromOIDPrefix(prefix string) string {
	parts := strings.Split(strings.TrimSpace(prefix), ".")
	buf := make([]byte, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n <= 31 || n > 255 {
			continue
		}
		buf = append(buf, byte(n))
	}
	return string(buf)
}

// CollectARP (Cisco L3 router): ifIndex->vlan[@vrf] через cviRoutedVlanIfIndex + mplsVpnInterfaceConfRowStatus, затем ARP по ipNetToMedia.
func (*ciscoARPL3Router) CollectARP(c *Client) (map[string]map[string]string, error) {
	ifd, err := c.Walk("1.3.6.1.4.1.9.9.128.1.1.1.1.3", "")
	if err != nil {
		return nil, err
	}
	arp, err := c.Walk("1.3.6.1.2.1.4.22.1.2", "")
	if err != nil {
		return nil, err
	}
	mvis, err := c.Walk("1.3.6.1.3.118.1.2.1.1.6", "")
	if err != nil {
		// На части платформ таблица VRF может отсутствовать; продолжаем без VRF-суффикса.
		mvis = map[string]string{}
	}

	vrfByIfIndex := map[string]string{}
	for k, v := range mvis {
		if strings.TrimSpace(v) != "1" {
			continue
		}
		pos := strings.LastIndex(k, ".")
		if pos <= 0 || pos >= len(k)-1 {
			continue
		}
		ifidx := strings.TrimSpace(k[pos+1:])
		name := decodeCiscoVRFNameFromOIDPrefix(k[:pos])
		if name != "" {
			vrfByIfIndex[ifidx] = name
		}
	}

	iv := map[string]string{}
	reIfd := regexp.MustCompile(`^(\d+)\.(\d+)$`)
	for key := range ifd {
		mm := reIfd.FindStringSubmatch(strings.TrimSpace(key))
		if len(mm) != 3 {
			continue
		}
		vlanName := mm[1]
		ifidx := mm[2]
		if vrf, ok := vrfByIfIndex[ifidx]; ok && vrf != "" {
			vlanName += "@" + vrf
		}
		iv[ifidx] = vlanName
	}

	return joinARPToVLAN(arp, iv), nil
}
