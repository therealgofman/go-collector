package snmp

import (
	"regexp"
	"strconv"
	"strings"
)

// -------------------------------- Huawei (интерфейсы / VLAN) --------------------------------
// --------------------aka get_huawei_vlan_table / get_huawei_vlan_table_s6300 ----------------

// HuaweiCloudEngineInterfaceNameKeep — только uplink/trunk-подобные имена.
var HuaweiCloudEngineInterfaceNameKeep = regexp.MustCompile(`(?:Eth-Trunk\d+|40GE\d/\d/\d+|XGigabitEthernet\d/\d/\d+|100GE\d/\d/\d+)`)

// huaweiIfaceHWL2 — Huawei: hwL2VlanPortList + hwL2IfPortType + PVID, опциональный фильтр имён.
type huaweiIfaceHWL2 struct {
	interfaceNameKeep *regexp.Regexp
}

// NewHuaweiIfaceHWL2 возвращает стратегию HW L2; interfaceNameKeep может быть nil (все порты).
func NewHuaweiIfaceHWL2(interfaceNameKeep *regexp.Regexp) VendorIfaceCollector {
	return &huaweiIfaceHWL2{interfaceNameKeep: interfaceNameKeep}
}

// huaweiIfaceQBridge
type huaweiIfaceQBridge struct {
	bitmaskBEF bool // как bitmaskToArrayWithBEF(..., 1) — unpack "b*"
}

// NewHuaweiIfaceQBridge возвращает стратегию по Q-BRIDGE Current; bitmaskBEF — порядок бит в октетах маски.
func NewHuaweiIfaceQBridge(bitmaskBEF bool) VendorIfaceCollector {
	return &huaweiIfaceQBridge{bitmaskBEF: bitmaskBEF}
}

// huaweiQBridgeOIDs — OID для huaweiIfaceQBridge.CollectInterfaces.
var huaweiQBridgeOIDs = mergeIfaceOIDMaps(
	qBridgeBaseIfOIDs,
	map[string]string{
		"hwL2IfPortIfIndex": "1.3.6.1.4.1.2011.5.25.42.1.1.1.3.1.2",
	},
)

// CollectInterfaces (Q-BRIDGE): Current egress/untagged, слияние dot1qPvid в egress,
// фильтр ifType 6|62|117, hwL2IfPortIfIndex reverse → индекс в битовых масках, tag при egress && !untag.
func (h *huaweiIfaceQBridge) CollectInterfaces(c *Client) (InterfacePorts, error) {
	opts := qBridgeDefaultCurrentOptions(
		map[string]string{
			"hwL2IfPortIfIndex": "1.3.6.1.4.1.2011.5.25.42.1.1.1.3.1.2",
		},
		qBridgeIfTypesL2Extended,
	)
	opts.OIDs = huaweiQBridgeOIDs
	opts.BitmaskBEF = h.bitmaskBEF
	opts.PositionByIfIndex = func(ifidx string, w map[string]map[string]string) (int, bool) {
		// Huawei в масках VLAN использует индекс hwL2-порта, а не напрямую ifIndex.
		for hwPortIdx, mappedIfidx := range w["hwL2IfPortIfIndex"] {
			if strings.TrimSpace(mappedIfidx) != strings.TrimSpace(ifidx) {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(hwPortIdx))
			if err != nil || n < 0 {
				return 0, false
			}
			return n, true
		}
		return 0, false
	}
	return collectInterfacesQBridgeGeneric(c, opts)
}

// huaweiInterfaceOIDs — набор OID для Huawei L2/VLAN (hwL2*, dot1q PVID и т.д.).
var huaweiInterfaceOIDs = map[string]string{
	"hwL2VlanPortList":  "1.3.6.1.4.1.2011.5.25.42.3.1.1.1.1.3",
	"dot1qPvid":         "1.3.6.1.2.1.17.7.1.4.5.1.1",
	"ifAdminStatus":     "1.3.6.1.2.1.2.2.1.7",
	"ifAlias":           "1.3.6.1.2.1.31.1.1.1.18",
	"ifType":            "1.3.6.1.2.1.2.2.1.3",
	"hwL2IfPortIfIndex": "1.3.6.1.4.1.2011.5.25.42.1.1.1.3.1.2",
	"ifName":            "1.3.6.1.2.1.31.1.1.1.1",
	"hwL2IfPortType":    "1.3.6.1.4.1.2011.5.25.42.1.1.1.3.1.3",
}

// CollectInterfaces (HW L2): маски hwL2VlanPortList по VLAN, PVID в egress, опционально фильтр по имени.
func (h *huaweiIfaceHWL2) CollectInterfaces(c *Client) (InterfacePorts, error) {
	w, err := walkMany(c, huaweiInterfaceOIDs, "")
	if err != nil {
		return nil, err
	}
	h2i := map[string]string{}
	for k, v := range w["hwL2IfPortIfIndex"] {
		h2i[v] = k
	}
	ports := InterfacePorts{}
	for ifidx := range w["ifType"] {
		n, _ := strconv.Atoi(ifidx)
		p := InterfacePort{
			VLANs:   map[int]int{},
			Name:    w["ifName"][ifidx],
			Descr:   w["ifAlias"][ifidx],
			IfIndex: n,
		}
		if w["ifAdminStatus"][ifidx] != "1" {
			p.Disabled = true
		}
		ports[ifidx] = p
	}
	pe := map[int][]string{}
	vlanSuffixRe := regexp.MustCompile(`(\d+)$`)
	for key, rawMask := range w["hwL2VlanPortList"] {
		mm := vlanSuffixRe.FindStringSubmatch(strings.TrimSpace(key))
		if len(mm) != 2 {
			continue
		}
		vid, _ := strconv.Atoi(mm[1])
		if vid <= 0 {
			continue
		}
		mask := bitmaskToArray(rawMask)
		for pvidKey, pvidValue := range w["dot1qPvid"] {
			if pvidValue == strconv.Itoa(vid) {
				idx, err := strconv.Atoi(pvidKey)
				if err == nil && idx >= 1 && idx <= len(mask) {
					mask[idx-1] = "1"
				}
			}
		}
		pe[vid] = mask
	}

	for vid, portList := range pe {
		if vid == 1 {
			continue
		}
		for ifidx := range ports {
			ifnum, ok := h2i[ifidx]
			if !ok {
				continue
			}
			n, err := strconv.Atoi(ifnum)
			if err != nil || n < 0 || n >= len(portList) {
				continue
			}
			egress := portList[n]
			pt, _ := strconv.Atoi(w["hwL2IfPortType"][ifnum])
			if pt == 1 {
				p := ports[ifidx]
				p.Tagged = true
				ports[ifidx] = p
			}
			if egress == "1" && (pt == 1 || pt == 2) {
				p := ports[ifidx]
				p.VLANs[vid] = 1
				ports[ifidx] = p
			}
		}
	}
	out := InterfacePorts{}
	for ifidx, p := range ports {
		if h.interfaceNameKeep != nil && !h.interfaceNameKeep.MatchString(p.Name) {
			continue
		}
		out[ifidx] = p
	}
	return out, nil
}
