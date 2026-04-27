package snmp

import (
	"fmt"
	"strconv"
	"strings"
)

// -------------------------------- MAC (FDB) ------------------------------
// ------------------------ aka ObjectInfo: fdb='generic' ------------------
var fdbOIDs = map[string]string{
	"dot1dTpFdbPort":       "1.3.6.1.2.1.17.4.3.1.2",
	"dot1dTpFdbStatus":     "1.3.6.1.2.1.17.4.3.1.3",
	"dot1dBasePortIfIndex": "1.3.6.1.2.1.17.1.4.1.2",
}

// bridgeMIBMAC — VendorMACCollector: FDB по BRIDGE-MIB (dot1dTpFdb*, dot1dBasePortIfIndex).
// fdbIdxCommunity: отдельный walk на каждый VLAN с community@vid; fdbWalkUsesGetBulk — GETBULK (true) или GETNEXT (false) для FDB.
type bridgeMIBMAC struct {
	fdbIdxCommunity    bool
	fdbWalkUsesGetBulk bool
}

// NewBridgeMIBMAC (aka generic) возвращает стратегию MAC/FDB; параметры как у прежнего genericFDB в фабрике.
func NewBridgeMIBMAC(fdbIdxCommunity, fdbWalkUsesGetBulk bool) VendorMACCollector {
	return &bridgeMIBMAC{fdbIdxCommunity: fdbIdxCommunity, fdbWalkUsesGetBulk: fdbWalkUsesGetBulk}
}

// CollectMAC (bridgeMIBMAC) обходит FDB OID, строит записи port_id/vlan/mac/status (MacTableFormatFDB) для persist;
// при fdbIdxCommunity использует ctx.IdxcomVLANWalks и выставляет meta.obsolete_by_vlan.
func (b *bridgeMIBMAC) CollectMAC(c *Client, ctx *MacDbContext) (MACTable, error) {
	if ctx == nil {
		return MACTable{}, fmt.Errorf("mac_db_context is required")
	}
	useBulkWalk := b.fdbWalkUsesGetBulk
	entries := make([]MACEntry, 0)
	parse := func(community string, fixedVLAN *int, fixedVLANID *int) error {
		w, err := walkNamedOIDs(c, fdbOIDs, community, &useBulkWalk)
		if err != nil {
			return err
		}
		for macSuffix, portV := range w["dot1dTpFdbPort"] {
			parts := strings.Split(macSuffix, ".")
			if len(parts) != 6 {
				continue
			}
			macBytes := make([]int, 0, 6)
			ok := true
			for _, p := range parts {
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
			if v, ok := w["dot1dBasePortIfIndex"][strconv.Itoa(brPort)]; ok {
				if t, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					ifidx = t
				}
			}
			if ifidx <= 0 {
				continue
			}
			status, _ := strconv.Atoi(strings.TrimSpace(w["dot1dTpFdbStatus"][macSuffix]))
			vlan := 0
			if fixedVLAN != nil {
				vlan = *fixedVLAN
			} else if vv, ok := ctx.IfIndexToUntaggedVLAN[ifidx]; ok {
				vlan = vv
			} else {
				vlan = 9999
			}
			row := MACEntry{
				IfIndex: ifidx,
				VLAN:    vlan,
				MAC:     mac,
				Status:  status,
			}
			if pid, ok := ctx.IfIndexToPortID[ifidx]; ok {
				row.PortID = pid
			}
			if fixedVLANID != nil {
				row.VLANID = *fixedVLANID
			}
			entries = append(entries, row)
		}
		return nil
	}
	meta := MACMeta{ObsoleteByVLAN: false}
	if b.fdbIdxCommunity {
		meta.ObsoleteByVLAN = true
		if len(ctx.IdxcomVLANWalks) == 0 {
			meta.Warning = "idxcom enabled but no VLANs from DB (query: get_vlan_list_for_mac_idxcom)"
			return MACTable{Format: MacTableFormatFDB, Entries: entries, Meta: meta}, nil
		}
		for _, pair := range ctx.IdxcomVLANWalks {
			vn := pair[0]
			vdb := pair[1]
			comm := fmt.Sprintf("%s@%d", c.Community, vn)
			if err := parse(comm, &vn, &vdb); err != nil {
				return MACTable{}, err
			}
		}
	} else if err := parse("", nil, nil); err != nil {
		return MACTable{}, err
	}

	fallbackByVLANIfIndex := map[int]map[int]int{}
	for _, row := range entries {
		if row.VLAN != 9999 {
			continue
		}
		ifidx := strings.TrimSpace(fmt.Sprint(row.IfIndex))
		if ifidx == "" {
			ifidx = "0"
		}
		if _, ok := fallbackByVLANIfIndex[9999]; !ok {
			fallbackByVLANIfIndex[9999] = map[int]int{}
		}
		if n, err := strconv.Atoi(ifidx); err == nil {
			fallbackByVLANIfIndex[9999][n]++
		}
	}
	if len(fallbackByVLANIfIndex) > 0 {
		meta.FallbackVLANIfIndexCounts = fallbackByVLANIfIndex
	}
	return MACTable{Format: MacTableFormatFDB, Entries: entries, Meta: meta}, nil
}
