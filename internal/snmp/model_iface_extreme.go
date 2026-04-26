package snmp

import (
	"go-collector/internal/helpers"
	"regexp"
	"strconv"
	"strings"
)

// -------------------------------- Extreme (интерфейсы / VLAN) -------------------------------
// -------------------------------- aka get_extreme_vlan_table --------------------------------
type extremeIface struct{ typ int }
type extremeXSeriesIface struct{}

func NewExtremeIface(typ int) VendorIfaceCollector { return &extremeIface{typ: typ} }
func NewExtremeXSeriesIface() VendorIfaceCollector { return &extremeXSeriesIface{} }

func (*extremeXSeriesIface) CollectInterfaces(c *Client) (map[string]any, error) {
	return (&extremeIface{typ: 3}).CollectInterfaces(c)
}

func (e *extremeIface) CollectInterfaces(c *Client) (map[string]any, error) {
	vlansOID := "1.3.6.1.4.1.1916.1.2.3.1.1.3"
	if e.typ == 3 {
		vlansOID = "1.3.6.1.4.1.1916.1.2.1.2.1.10"
	}

	w, err := walkMany(c, mergeIfaceOIDMaps(qBridgeBaseIfOIDs, map[string]string{
		"vlans":    vlansOID,
		"t":        "1.3.6.1.4.1.1916.1.2.6.1.1.1",
		"u":        "1.3.6.1.4.1.1916.1.2.6.1.1.2",
		"dot1port": "1.3.6.1.2.1.17.1.4.1.2",
	}), "")
	if err != nil {
		return nil, err
	}

	vlanMap := map[string]string{}
	if e.typ != 3 {
		vlanMapRaw, err := c.Walk("1.3.6.1.4.1.1916.1.2.7.1.1.2", "")
		if err != nil {
			return nil, err
		}
		re := regexp.MustCompile(`\.\d+$`)
		for key, mapped := range vlanMapRaw {
			internalVID := re.ReplaceAllString(key, "")
			vlanMap[strings.TrimSpace(mapped)] = internalVID
		}
	}

	ve := map[int][]string{}
	vu := map[int][]string{}
	for key, vlanValue := range w["vlans"] {
		vid, err := strconv.Atoi(strings.TrimSpace(vlanValue))
		if err != nil || vid <= 0 {
			continue
		}
		internalVID := key
		if e.typ != 3 {
			var ok bool
			internalVID, ok = vlanMap[key]
			if !ok {
				continue
			}
		}
		maskKey := internalVID + ".1"
		if raw, ok := w["t"][maskKey]; ok {
			ve[vid] = bitmaskToArray(raw)
		}
		if raw, ok := w["u"][maskKey]; ok {
			vu[vid] = bitmaskToArray(raw)
		}
	}

	bridgePortByIfIndex := map[int]int{}
	for bridgePortS, ifIndexS := range w["dot1port"] {
		bridgePort, err1 := strconv.Atoi(strings.TrimSpace(bridgePortS))
		ifIndex, err2 := strconv.Atoi(strings.TrimSpace(ifIndexS))
		if err1 != nil || err2 != nil || bridgePort <= 0 || ifIndex <= 0 {
			continue
		}
		bridgePortByIfIndex[ifIndex] = bridgePort
	}

	ports := map[string]map[string]any{}
	for ifidxS, ifname := range w["ifName"] {
		ifType := strings.TrimSpace(w["ifType"][ifidxS])
		if _, ok := qBridgeIfTypesL2Basic[ifType]; !ok {
			continue
		}
		ifidx, err := strconv.Atoi(strings.TrimSpace(ifidxS))
		if err != nil || ifidx <= 0 {
			continue
		}
		p := map[string]any{
			"name":    ifname,
			"ifindex": ifidx,
			"vlan":    map[int]int{},
			"descr":   w["ifAlias"][ifidxS],
		}
		if strings.TrimSpace(w["ifAdminStatus"][ifidxS]) == "2" {
			p["disab"] = 1
		}
		ports[ifname] = p
	}

	for vid, eArr := range ve {
		uArr := vu[vid]
		for _, p := range ports {
			ifidx, ok := helpers.AsInt(p["ifindex"])
			if !ok {
				continue
			}
			bridgePort, ok := bridgePortByIfIndex[ifidx]
			if !ok || bridgePort <= 0 {
				continue
			}
			pos := bridgePort - 1
			egress := pos < len(eArr) && eArr[pos] == "1"
			untag := pos < len(uArr) && uArr[pos] == "1"
			if egress && !untag {
				p["tag"] = 1
			}
			if egress || untag {
				p["vlan"].(map[int]int)[vid] = 1
			}
		}
	}

	return helpers.PortsToAnyMap(ports), nil
}
