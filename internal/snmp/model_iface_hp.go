package snmp

import (
	"go-collector/internal/helpers"
	"regexp"
	"strconv"
	"strings"
)

// -------------------------------- Hewlett Packard Enterprise (интерфейсы / VLAN) ----------------

var hpeQBridgeInterfaceOIDs = map[string]string{
	"dot1qVlanStaticEgressPorts":   "1.3.6.1.2.1.17.7.1.4.3.1.2",
	"dot1qVlanStaticUntaggedPorts": "1.3.6.1.2.1.17.7.1.4.3.1.4",
	"dot1qPvid":                    "1.3.6.1.2.1.17.7.1.4.5.1.1",
	"dot1dBasePortIfIndex":         "1.3.6.1.2.1.17.1.4.1.2",
	"ifAdminStatus":                "1.3.6.1.2.1.2.2.1.7",
	"ifOperStatus":                 "1.3.6.1.2.1.2.2.1.8",
	"ifHighSpeed":                  "1.3.6.1.2.1.31.1.1.1.15",
	"ifAlias":                      "1.3.6.1.2.1.31.1.1.1.18",
	"ifName":                       "1.3.6.1.2.1.31.1.1.1.1",
	"ifType":                       "1.3.6.1.2.1.2.2.1.3",
}

var hpe5900InterfaceNameKeep = regexp.MustCompile(`^(?:Ten-GigabitEthernet|FortyGigE|Bridge-Aggregation)`)

type hpeIfaceQBridgeStatic struct {
	interfaceNameKeep *regexp.Regexp
}

// NewHPEIfaceQBridgeStatic возвращает общий Q-BRIDGE static collector для HPE-линейки.
// interfaceNameKeep можно переиспользовать для будущих HPE-моделей.
func NewHPEIfaceQBridgeStatic(interfaceNameKeep *regexp.Regexp) VendorIfaceCollector {
	return &hpeIfaceQBridgeStatic{interfaceNameKeep: interfaceNameKeep}
}

// NewHPE5900IfaceQBridgeStatic возвращает профиль collector'а для HPE 5900.
func NewHPE5900IfaceQBridgeStatic() VendorIfaceCollector {
	return NewHPEIfaceQBridgeStatic(hpe5900InterfaceNameKeep)
}

func (h *hpeIfaceQBridgeStatic) CollectInterfaces(c *Client) (map[string]any, error) {
	w, err := walkMany(c, hpeQBridgeInterfaceOIDs, "")
	if err != nil {
		return nil, err
	}

	pe, pu := ifaceQBridgeRawVLANTables(
		w["dot1qVlanStaticEgressPorts"],
		w["dot1qVlanStaticUntaggedPorts"],
		w["dot1qPvid"],
		false,
	)

	ports := map[string]map[string]any{}
	bridgePortPosByIfIndex := map[string]int{}
	for bridgePortS, ifindex := range w["dot1dBasePortIfIndex"] {
		bridgePort, err := strconv.Atoi(strings.TrimSpace(bridgePortS))
		if err != nil || bridgePort <= 0 {
			continue
		}
		bridgePortPosByIfIndex[ifindex] = bridgePort - 1
	}

	for ifidx, name := range w["ifName"] {
		if strings.TrimSpace(w["ifType"][ifidx]) != "6" && strings.TrimSpace(w["ifType"][ifidx]) != "161" {
			continue
		}
		if h.interfaceNameKeep != nil && !h.interfaceNameKeep.MatchString(name) {
			continue
		}

		n, _ := strconv.Atoi(ifidx)
		p := map[string]any{
			"name":         name,
			"descr":        w["ifAlias"][ifidx],
			"ifindex":      n,
			"vlan":         map[int]int{},
			"ifspeed":      strings.TrimSpace(w["ifHighSpeed"][ifidx]),
			"ifadm_status": strings.TrimSpace(w["ifAdminStatus"][ifidx]),
			"ifop_status":  strings.TrimSpace(w["ifOperStatus"][ifidx]),
		}
		if strings.TrimSpace(w["ifAdminStatus"][ifidx]) != "1" {
			p["disab"] = 1
		}
		ports[ifidx] = p
	}

	for vid, eArr := range pe {
		if vid < 1 || vid > 4094 {
			continue
		}
		uArr := pu[vid]
		for ifidx, p := range ports {
			pos, ok := bridgePortPosByIfIndex[ifidx]
			if !ok || pos < 0 {
				continue
			}
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
