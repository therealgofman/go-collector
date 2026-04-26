package snmp

import (
	"go-collector/internal/helpers"
	"strconv"
	"strings"
)

// -------------------------------- SNR (интерфейсы / VLAN) -------------------------------
// -------------------------------- aka get_snr_table -------------------------------------
type snrIface struct{}
type snrIfaceQBridge struct{}

func NewSNRIface() VendorIfaceCollector        { return &snrIface{} }
func NewSNRIfaceQBridge() VendorIfaceCollector { return &snrIfaceQBridge{} }

func (*snrIfaceQBridge) CollectInterfaces(c *Client) (map[string]any, error) {
	return NewQBridgeIfaceCurrentDefault(QBridgeIfTypesL2StackLike()).CollectInterfaces(c)
}

func (*snrIface) CollectInterfaces(c *Client) (map[string]any, error) {
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

	ports := map[string]map[string]any{}
	for ifidx, name := range w["ifName"] {
		n, _ := strconv.Atoi(ifidx)
		p := map[string]any{
			"ifindex": n,
			"vlan":    map[int]int{},
			"name":    name,
		}
		if ifAlias, ok := w["ifAlias"][ifidx]; ok {
			p["descr"] = ifAlias
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
		ports[ifi]["vlan"].(map[int]int)[vid] = 1

		if ismVID, ok := pvidISM[ifi]; ok {
			if ism, err := strconv.Atoi(strings.TrimSpace(ismVID)); err == nil && ism > 0 {
				ports[ifi]["vlan"].(map[int]int)[ism] = 1
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
				p["tag"] = 1
				p["vlan"].(map[int]int)[vid] = 1
			}
		}
	}

	return helpers.PortsToAnyMap(ports), nil
}
