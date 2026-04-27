package snmp

import (
	"regexp"
	"strings"
)

type extremeARP struct{}
type extremeXSeriesARP struct{}

// NewExtremeARP возвращает ARP-стратегию Extreme (extremeVlanIfVlanId + ipNetToMediaPhysAddress).
func NewExtremeARP() VendorARPCollector { return &extremeARP{} }

// NewExtremeXSeriesARP возвращает ARP-стратегию Extreme X series (extremeFdbIpFdb*).
func NewExtremeXSeriesARP() VendorARPCollector { return &extremeXSeriesARP{} }

// CollectARP (Extreme): iv[ifIndex]=vlanIf по ключу vlanIf.ifIndex, затем arp ifIndex.ip -> mac.
func (*extremeARP) CollectARP(c *Client) (ARPTable, error) {
	ifd, err := c.Walk("1.3.6.1.4.1.1916.1.2.1.2.1.10", "")
	if err != nil {
		return ARPTable{}, err
	}
	arp, err := c.Walk("1.3.6.1.2.1.4.22.1.2", "")
	if err != nil {
		return ARPTable{}, err
	}

	re := regexp.MustCompile(`^(\d+)\.(\d+)$`)
	iv := map[string]string{}
	for k, v := range ifd {
		mm := re.FindStringSubmatch(strings.TrimSpace(k))
		if len(mm) != 3 {
			continue
		}
		iv[strings.TrimSpace(v)] = mm[1]
	}
	return ARPTable{Entries: joinARPToVLAN(arp, iv)}, nil
}

// CollectARP (Extreme X series): ip/mac/vlanIfIndex таблицы private MIB + map vlanIf->VLAN.
func (*extremeXSeriesARP) CollectARP(c *Client) (ARPTable, error) {
	w, err := walkNamedOIDs(c, map[string]string{
		"vlan":    "1.3.6.1.4.1.1916.1.2.1.2.1.10",
		"ip":      "1.3.6.1.4.1.1916.1.16.2.1.2",
		"mac":     "1.3.6.1.4.1.1916.1.16.2.1.3",
		"vlanifi": "1.3.6.1.4.1.1916.1.16.2.1.4",
	}, "", nil)
	if err != nil {
		return ARPTable{}, err
	}

	iv := map[string]string{}
	rePair := regexp.MustCompile(`^(\d+)\.(\d+)$`)
	reSingle := regexp.MustCompile(`^(\d+)$`)
	for k, v := range w["vlan"] {
		kk := strings.TrimSpace(k)
		if mm := rePair.FindStringSubmatch(kk); len(mm) == 3 {
			iv[mm[1]] = strings.TrimSpace(v)
			continue
		}
		if mm := reSingle.FindStringSubmatch(kk); len(mm) == 2 {
			iv[mm[1]] = strings.TrimSpace(v)
		}
	}

	out := map[string]map[string]string{}
	for key, ip := range w["ip"] {
		vlanIfIdx, ok := w["vlanifi"][key]
		if !ok {
			continue
		}
		vlan, ok := iv[strings.TrimSpace(vlanIfIdx)]
		if !ok || strings.TrimSpace(vlan) == "" {
			continue
		}
		rawMAC, ok := w["mac"][key]
		if !ok {
			continue
		}
		mac, ok := formatExtremeMAC(rawMAC)
		if !ok {
			continue
		}
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := out[vlan]; !ok {
			out[vlan] = map[string]string{}
		}
		out[vlan][ip] = mac
	}
	return ARPTable{Entries: out}, nil
}
