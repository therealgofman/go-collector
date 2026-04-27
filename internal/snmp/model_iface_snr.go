package snmp

import (
	"strconv"
	"strings"
)

// -------------------------------- SNR (интерфейсы / VLAN) -------------------------------
// -------------------------------- aka get_snr_table -------------------------------------
type snrIface struct{}
type snrIfaceQBridge struct{}

func NewSNRIface() VendorIfaceCollector        { return &snrIface{} }
func NewSNRIfaceQBridge() VendorIfaceCollector { return &snrIfaceQBridge{} }

func (*snrIfaceQBridge) CollectInterfaces(c *Client) (InterfacePorts, error) {
	return NewQBridgeIfaceCurrentDefault(QBridgeIfTypesL2StackLike()).CollectInterfaces(c)
}

func (*snrIface) CollectInterfaces(c *Client) (InterfacePorts, error) {
	w, err := walkMany(c, map[string]string{
		"ifName":     "1.3.6.1.4.1.40418.7.100.3.2.1.2",
		"ifAlias":    "1.3.6.1.2.1.31.1.1.1.18",
		"vs":         "1.3.6.1.4.1.40418.7.100.5.1.1.2",
		"portMode":   "1.3.6.1.4.1.40418.7.100.3.2.1.15",
		"pvid":       "1.3.6.1.4.1.40418.7.100.3.2.1.16",
		"vpe":        "1.3.6.1.4.1.40418.7.100.3.2.1.20",
		"pvidISMRaw": "1.3.6.1.4.1.40418.7.100.5.3.1.4",
	}, "")
	if err != nil {
		return nil, err
	}

	pvidISM := map[string]string{}
	for key := range w["pvidISMRaw"] {
		parts := strings.Split(key, ".")
		if len(parts) != 2 {
			continue
		}
		pvidISM[parts[1]] = strings.TrimSpace(parts[0])
	}

	ports := InterfacePorts{}
	for ifidx, name := range w["ifName"] {
		n, _ := strconv.Atoi(ifidx)
		p := InterfacePort{
			IfIndex: n,
			VLANs:   map[int]int{},
			Name:    name,
		}
		if ifAlias, ok := w["ifAlias"][ifidx]; ok {
			p.Descr = ifAlias
		}
		ports[ifidx] = p
	}

	// Старые версии SNR отдают vpe как бинарную маску, новые — как ";"-список VLAN.
	semicolonVPE := false
	for _, raw := range w["vpe"] {
		if strings.Contains(raw, ";") {
			semicolonVPE = true
			break
		}
	}

	for ifi, pvidS := range w["pvid"] {
		if _, ok := ports[ifi]; !ok {
			continue
		}
		vid, err := strconv.Atoi(strings.TrimSpace(pvidS))
		if err != nil || vid <= 0 {
			continue
		}
		if _, existsInVS := w["vs"][pvidS]; !existsInVS && strings.TrimSpace(w["portMode"][ifi]) != "2" {
			continue
		}
		p := ports[ifi]
		p.VLANs[vid] = 1
		ports[ifi] = p

		if ismVID, ok := pvidISM[ifi]; ok {
			if ism, err := strconv.Atoi(strings.TrimSpace(ismVID)); err == nil && ism > 0 {
				p := ports[ifi]
				p.VLANs[ism] = 1
				ports[ifi] = p
			}
		}
	}

	for vidS := range w["vs"] {
		vid, err := strconv.Atoi(strings.TrimSpace(vidS))
		if err != nil || vid <= 0 {
			continue
		}
		for ifi, p := range ports {
			if strings.TrimSpace(w["portMode"][ifi]) != "2" {
				continue
			}
			includeVID := false
			if semicolonVPE {
				for _, item := range strings.Split(w["vpe"][ifi], ";") {
					if strings.TrimSpace(item) == vidS {
						includeVID = true
						break
					}
				}
			} else {
				arr := bitmaskToArray(w["vpe"][ifi])
				if vid < len(arr) && arr[vid] == "1" {
					includeVID = true
				}
			}
			if includeVID {
				p.Tagged = true
				p.VLANs[vid] = 1
				ports[ifi] = p
			}
		}
	}

	return ports, nil
}
