package snmp

import (
	"fmt"
	"strconv"
	"strings"
)

// -------------------------------- MAC (FDB) ------------------------------
// ------------- aka ObjectInfo: fdb='extreme' / fdb='extremex' ------------
var extremePrivateFdbOIDs = map[string]string{
	"addr":    "1.3.6.1.4.1.1916.1.16.1.1.3",
	"ifi":     "1.3.6.1.4.1.1916.1.16.1.1.4",
	"sta":     "1.3.6.1.4.1.1916.1.16.1.1.5",
	"vlans":   "1.3.6.1.4.1.1916.1.2.3.1.1.3",
	"vmapraw": "1.3.6.1.4.1.1916.1.2.7.1.1.2",
}

type extremePrivateMAC struct {
	useBulkWalk bool
}

// NewExtremePrivateMAC возвращает MAC/FDB сборщик для Extreme private MIB.
func NewExtremePrivateMAC(useBulkWalk bool) VendorMACCollector {
	return &extremePrivateMAC{useBulkWalk: useBulkWalk}
}

func formatExtremeMAC(raw string) (string, bool) {
	b := []byte(raw)
	if len(b) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]), true
	}
	h := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(raw), "0x", ""), ":", ""), "-", ""))
	if len(h) != 12 {
		return "", false
	}
	for _, r := range h {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return "", false
		}
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", h[0:2], h[2:4], h[4:6], h[6:8], h[8:10], h[10:12]), true
}

// CollectMAC ifindex/vlan/mac/status по Extreme private MIB.
func (e *extremePrivateMAC) CollectMAC(c *Client, ctx *MacDbContext) (MACTable, error) {
	if ctx == nil {
		return MACTable{}, fmt.Errorf("mac_db_context is required")
	}
	useBulkWalk := e.useBulkWalk
	w, err := walkNamedOIDs(c, extremePrivateFdbOIDs, "", &useBulkWalk)
	if err != nil {
		return MACTable{}, err
	}

	// map intVlanLowIndex -> VLAN number.
	vlanMap := map[string]int{}
	for idx, lowIdx := range w["vmapraw"] {
		highIdx := idx
		if dot := strings.LastIndex(highIdx, "."); dot > 0 {
			highIdx = highIdx[:dot]
		}
		vlanNumS, ok := w["vlans"][strings.TrimSpace(lowIdx)]
		if !ok {
			continue
		}
		vlanNum, err := strconv.Atoi(strings.TrimSpace(vlanNumS))
		if err != nil || vlanNum <= 0 {
			continue
		}
		vlanMap[strings.TrimSpace(highIdx)] = vlanNum
	}

	entries := make([]MACEntry, 0, len(w["ifi"]))
	for key, ifidxS := range w["ifi"] {
		macRaw, ok := w["addr"][key]
		if !ok {
			continue
		}
		mac, ok := formatExtremeMAC(macRaw)
		if !ok {
			continue
		}
		ifidx, err := strconv.Atoi(strings.TrimSpace(ifidxS))
		if err != nil || ifidx <= 0 {
			continue
		}

		lowIdx := key
		if dot := strings.LastIndex(lowIdx, "."); dot > 0 {
			lowIdx = lowIdx[:dot]
		}
		vlan, ok := vlanMap[strings.TrimSpace(lowIdx)]
		if !ok {
			continue
		}

		row := MACEntry{
			IfIndex: ifidx,
			VLAN:    vlan,
			MAC:     mac,
			Status:  3,
		}
		if pid, ok := ctx.IfIndexToPortID[ifidx]; ok {
			row.PortID = pid
		}
		entries = append(entries, row)
	}
	return MACTable{
		Format:  MacTableFormatFDB,
		Entries: entries,
		Meta:    MACMeta{ObsoleteByVLAN: false},
	}, nil
}

// -------------------------------------------------- Extreme X series --------------------------------------------------
var extremeXSeriesFdbOIDs = map[string]string{
	"vid":    "1.3.6.1.4.1.1916.1.2.1.2.1.10",
	"port":   "1.3.6.1.4.1.1916.1.16.4.1.3",
	"status": "1.3.6.1.4.1.1916.1.16.4.1.4",
}

type extremeXSeriesMAC struct {
	useBulkWalk bool
}

// NewExtremeXSeriesMAC возвращает MAC/FDB сборщик для Extreme X series.
func NewExtremeXSeriesMAC(useBulkWalk bool) VendorMACCollector {
	return &extremeXSeriesMAC{useBulkWalk: useBulkWalk}
}

// CollectMAC ifindex/vlan/mac/status по Extreme EXOS private MIB.
func (e *extremeXSeriesMAC) CollectMAC(c *Client, ctx *MacDbContext) (MACTable, error) {
	if ctx == nil {
		return MACTable{}, fmt.Errorf("mac_db_context is required")
	}
	useBulkWalk := e.useBulkWalk
	w, err := walkNamedOIDs(c, extremeXSeriesFdbOIDs, "", &useBulkWalk)
	if err != nil {
		return MACTable{}, err
	}

	entries := make([]MACEntry, 0, len(w["status"]))
	for key, staS := range w["status"] {
		parts := strings.Split(strings.TrimSpace(key), ".")
		if len(parts) < 7 {
			continue
		}

		vlanIf := strings.TrimSpace(parts[len(parts)-1])
		macParts := parts[len(parts)-7 : len(parts)-1]
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

		vlanS, ok := w["vid"][vlanIf]
		if !ok {
			continue
		}
		vlan, err := strconv.Atoi(strings.TrimSpace(vlanS))
		if err != nil || vlan <= 0 {
			continue
		}

		status, err := strconv.Atoi(strings.TrimSpace(staS))
		if err != nil {
			status = 0
		}

		ifidx := 0
		if ifS, ok := w["port"][key]; ok {
			if v, err := strconv.Atoi(strings.TrimSpace(ifS)); err == nil && v > 0 {
				ifidx = v
			}
		}
		// Совпадает с legacy: next if (!$if && $sta==3)
		if ifidx == 0 && status == 3 {
			continue
		}

		row := MACEntry{
			VLAN:   vlan,
			MAC:    mac,
			Status: status,
		}
		if ifidx > 0 {
			row.IfIndex = ifidx
			if pid, ok := ctx.IfIndexToPortID[ifidx]; ok {
				row.PortID = pid
			}
		}
		entries = append(entries, row)
	}
	return MACTable{
		Format:  MacTableFormatFDB,
		Entries: entries,
		Meta:    MACMeta{ObsoleteByVLAN: false},
	}, nil
}
