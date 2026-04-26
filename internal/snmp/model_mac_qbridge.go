package snmp

import (
	"fmt"
	"strconv"
	"strings"
)

// -------------------------------- MAC (FDB) -------------------------
// ------------- aka ObjectInfo: fdb='qbridge' ------------------------
var qbridgeFdbOIDs = map[string]string{
	"dot1qTpFdbPort":     "1.3.6.1.2.1.17.7.1.2.2.1.2",
	"dot1qTpFdbStatus":   "1.3.6.1.2.1.17.7.1.2.2.1.3",
	"dot1dBasePortIfIdx": "1.3.6.1.2.1.17.1.4.1.2",
}

// qbridgeMAC — общий VendorMACCollector для устройств с Q-BRIDGE FDB (vlan.decimal-mac -> dot1d port).
type qbridgeMAC struct {
	fdbWalkUsesGetBulk bool
}

// NewQBridgeMAC возвращает общий MAC/FDB сборщик Q-BRIDGE.
func NewQBridgeMAC(fdbWalkUsesGetBulk bool) VendorMACCollector {
	return &qbridgeMAC{fdbWalkUsesGetBulk: fdbWalkUsesGetBulk}
}

// CollectMAC (Q-BRIDGE): VLAN берётся из префикса ключа FDB, ifIndex — через dot1dBasePortIfIndex.
func (m *qbridgeMAC) CollectMAC(c *Client, ctx *MacDbContext) (map[string]any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("mac_db_context is required")
	}
	useBulkWalk := m.fdbWalkUsesGetBulk
	w, err := walkNamedOIDs(c, qbridgeFdbOIDs, "", &useBulkWalk)
	if err != nil {
		return nil, err
	}

	entries := make([]any, 0, len(w["dot1qTpFdbPort"]))
	for key, portV := range w["dot1qTpFdbPort"] {
		parts := strings.SplitN(strings.TrimSpace(key), ".", 2)
		if len(parts) != 2 {
			continue
		}
		vlan, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || vlan <= 0 {
			continue
		}
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
