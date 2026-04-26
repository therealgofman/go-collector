package snmp

import (
	"fmt"
	"strconv"
	"strings"
)

// -------------------------------- MAC (FDB) ----------------------------
// ------------- aka ObjectInfo: fdb='qbridge_jun' -----------------------
var juniperQBridgeFdbOIDs = map[string]string{
	"dot1qTpFdbPort":     "1.3.6.1.2.1.17.7.1.2.2.1.2",
	"dot1qTpFdbStatus":   "1.3.6.1.2.1.17.7.1.2.2.1.3",
	"dot1dBasePortIfIdx": "1.3.6.1.2.1.17.1.4.1.2",
	"jnxL2aldVlanTag":    "1.3.6.1.4.1.2636.3.48.1.3.1.1.3",
	"jnxL2aldVlanFdbId":  "1.3.6.1.4.1.2636.3.48.1.3.1.1.5",
}

// juniperQBridgeMAC — VendorMACCollector: Q-BRIDGE FDB + jnxL2aldVlanTag/FdbId для Juniper.
type juniperQBridgeMAC struct {
	fdbWalkUsesGetBulk bool
}

// NewJuniperQBridgeMAC возвращает стратегию MAC/FDB для Juniper (fdbWalkUsesGetBulk: GETBULK vs GETNEXT для обхода FDB).
func NewJuniperQBridgeMAC(fdbWalkUsesGetBulk bool) VendorMACCollector {
	return &juniperQBridgeMAC{fdbWalkUsesGetBulk: fdbWalkUsesGetBulk}
}

// CollectMAC (juniperQBridgeMAC) строит FDB-строки ifindex/vlan/mac/status по Juniper Q-BRIDGE.
func (j *juniperQBridgeMAC) CollectMAC(c *Client, ctx *MacDbContext) (map[string]any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("mac_db_context is required")
	}
	useBulkWalk := j.fdbWalkUsesGetBulk
	w, err := walkNamedOIDs(c, juniperQBridgeFdbOIDs, "", &useBulkWalk)
	if err != nil {
		return nil, err
	}

	fdbIDToVLAN := map[string]int{}
	for rowIdx, fdbID := range w["jnxL2aldVlanFdbId"] {
		tagS, ok := w["jnxL2aldVlanTag"][rowIdx]
		if !ok {
			continue
		}
		tag, err := strconv.Atoi(strings.TrimSpace(tagS))
		if err != nil || tag <= 0 {
			continue
		}
		fdbIDToVLAN[strings.TrimSpace(fdbID)] = tag
	}

	entries := make([]any, 0, len(w["dot1qTpFdbPort"]))
	for key, portV := range w["dot1qTpFdbPort"] {
		parts := strings.SplitN(strings.TrimSpace(key), ".", 2)
		if len(parts) != 2 {
			continue
		}
		fdbID := strings.TrimSpace(parts[0])
		macParts := strings.Split(strings.TrimSpace(parts[1]), ".")
		if len(macParts) != 6 {
			continue
		}
		macBytes := make([]int, 0, 6)
		ok := true
		for _, p := range macParts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				ok = false
				break
			}
			macBytes = append(macBytes, n)
		}
		if !ok {
			continue
		}
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", macBytes[0], macBytes[1], macBytes[2], macBytes[3], macBytes[4], macBytes[5])

		brPort, _ := strconv.Atoi(strings.TrimSpace(portV))
		ifidx := brPort
		if v, ok := w["dot1dBasePortIfIdx"][strconv.Itoa(brPort)]; ok {
			if t, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				ifidx = t
			}
		}
		if ifidx <= 0 {
			continue
		}

		status := 0
		if sv, ok := w["dot1qTpFdbStatus"][key]; ok {
			if s, err := strconv.Atoi(strings.TrimSpace(sv)); err == nil {
				status = s
			}
		}
		vlan := 9999
		if v, ok := fdbIDToVLAN[fdbID]; ok {
			vlan = v
		}

		row := map[string]any{
			"ifindex": ifidx,
			"vlan":    vlan,
			"mac":     mac,
			"status":  status,
		}
		if pid, ok := ctx.IfIndexToPortID[ifidx]; ok {
			row["port_id"] = pid
		}
		entries = append(entries, row)
	}

	return map[string]any{
		"format":  MacTableFormatFDB,
		"entries": entries,
		"meta":    map[string]any{"obsolete_by_vlan": false},
	}, nil
}
