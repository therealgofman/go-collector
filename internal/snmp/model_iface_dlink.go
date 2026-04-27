package snmp

import (
	"regexp"
	"strconv"
	"strings"
)

// -------------------------------- D-Link (интерфейсы / VLAN) --------------------------------
// aka get_dlink_1210_vlan_table / get_dlink_3100_vlan_table / get_dlink_3028_vlan_table
// get_dlink_2108_vlan_table / get_dlink_1100_vlan_table

// typ выбирает ветку enterprise-MIB для 1210-like семейств:
// 0=75.5 (default), 1=75.15, 2=75.15.2, 10=75.14, 11=75.14.1, 12=76.44.1.
type dlinkIface1210 struct{ typ int }
type dlinkIface3100 struct {
	enrich3120Portnames bool
	enrich3120ISM       bool
}
type dlinkIface3028 struct{}

// newMIB переключает базовый OID для DES-2108:
// false -> ...171.10.61.2... (старый профиль), true -> ...171.10.61.3... (новый профиль).
type dlinkIface2108 struct{ newMIB bool }
type dlinkIface1100 struct{}

// NewDLinkIface1210 принимает typ для выбора MIB-профиля модели (см. комментарий у dlinkIface1210.typ).
func NewDLinkIface1210(typ int) VendorIfaceCollector { return &dlinkIface1210{typ: typ} }
func NewDLinkIface3100(enrich3120Portnames, enrich3120ISM bool) VendorIfaceCollector {
	return &dlinkIface3100{enrich3120Portnames: enrich3120Portnames, enrich3120ISM: enrich3120ISM}
}
func NewDLinkIface3028() VendorIfaceCollector { return &dlinkIface3028{} }

// NewDLinkIface2108 включает новый OID-профиль DES-2108 при newMIB=true.
func NewDLinkIface2108(newMIB bool) VendorIfaceCollector { return &dlinkIface2108{newMIB: newMIB} }
func NewDLinkIface1100() VendorIfaceCollector            { return &dlinkIface1100{} }

func dlink1210MIBSuffixByType(typ int) string {
	m := map[int]string{2: "75.15.2", 10: "75.14", 11: "75.14.1", 1: "75.15", 0: "75.5", 12: "76.44.1"}
	if s, ok := m[typ]; ok {
		return s
	}
	return m[0]
}

func (d *dlinkIface1210) CollectInterfaces(c *Client) (InterfacePorts, error) {
	prefix := "1.3.6.1.4.1.171.10." + dlink1210MIBSuffixByType(d.typ)
	w, err := walkMany(c, map[string]string{
		"ifType": "1.3.6.1.2.1.2.2.1.3",
		"ifName": prefix + ".1.14.1.3",
		"vs":     prefix + ".7.6.1.5",
		"vpe":    prefix + ".7.6.1.2",
		"vpu":    prefix + ".7.6.1.4",
		"ism":    prefix + ".27.2.1.4",
	}, "")
	if err != nil {
		return nil, err
	}

	ports := InterfacePorts{}
	for ifidx, typ := range w["ifType"] {
		if strings.TrimSpace(typ) != "6" {
			continue
		}
		n, _ := strconv.Atoi(ifidx)
		p := InterfacePort{VLANs: map[int]int{}, Name: ifidx, IfIndex: n}
		for _, unit := range []string{"100", "101", "102"} {
			if desc := strings.TrimSpace(w["ifName"][ifidx+"."+unit]); desc != "" {
				p.Descr = desc
			}
		}
		ports[ifidx] = p
	}

	for vidS := range w["vs"] {
		vid, err := strconv.Atoi(strings.TrimSpace(vidS))
		if err != nil || vid <= 0 {
			continue
		}
		eArr := bitmaskToArray(w["vpe"][vidS])
		uArr := bitmaskToArray(w["vpu"][vidS])
		for ifidx, p := range ports {
			i, err := strconv.Atoi(ifidx)
			if err != nil || i <= 0 {
				continue
			}
			pos := i - 1
			egress := pos < len(eArr) && eArr[pos] == "1"
			untag := pos < len(uArr) && uArr[pos] == "1"
			if egress && !untag {
				p.Tagged = true
			}
			if egress || untag {
				p.VLANs[vid] = 1
			}
			ports[ifidx] = p
		}
	}
	for vidS, raw := range w["ism"] {
		vid, err := strconv.Atoi(strings.TrimSpace(vidS))
		if err != nil || vid <= 0 {
			continue
		}
		mask := bitmaskToArray(raw)
		for pos, bit := range mask {
			if bit != "1" {
				continue
			}
			ifidx := strconv.Itoa(pos + 1)
			p, ok := ports[ifidx]
			if !ok {
				continue
			}
			if p.Tagged {
				continue
			}
			p.VLANs[vid] = 1
			ports[ifidx] = p
		}
	}
	return ports, nil
}

// CollectInterfaces (с опциональными enrich_3120_*)
func (d *dlinkIface3100) CollectInterfaces(c *Client) (InterfacePorts, error) {
	w, err := walkMany(c, mergeIfaceOIDMaps(
		ifaceQBridgeCurrentOIDs,
		map[string]string{
			"ifAlias":       "1.3.6.1.2.1.31.1.1.1.18",
			"ifOperStatus":  "1.3.6.1.2.1.2.2.1.8",
			"ifType":        "1.3.6.1.2.1.2.2.1.3",
			"ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
		},
	), "")
	if err != nil {
		return nil, err
	}
	pe, pu := ifaceQBridgeRawVLANTables(w["dot1qVlanCurrentEgressPorts"], w["dot1qVlanCurrentUntaggedPorts"], w["dot1qPvid"], false)
	ports := dlinkMergePortsFromMasks(w["ifOperStatus"], w["ifAlias"], w["ifAdminStatus"], pe, pu, func(ifidx, oper string) bool {
		return strings.TrimSpace(oper) != "6" && strings.TrimSpace(w["ifType"][ifidx]) == "6"
	})
	if err := d.collectWithEnrich(c, ports); err != nil {
		return nil, err
	}
	return ports, nil
}

func (d *dlinkIface3100) collectWithEnrich(c *Client, ports InterfacePorts) error {
	if d.enrich3120Portnames {
		next, changed, err := dlinkEnrich3120Portnames(c, ports)
		if err != nil {
			return err
		}
		if changed {
			for k := range ports {
				delete(ports, k)
			}
			for k, v := range next {
				ports[k] = v
			}
		}
	}
	if d.enrich3120ISM {
		return dlinkEnrich3120ISM(c, ports)
	}
	return nil
}

func (*dlinkIface3028) CollectInterfaces(c *Client) (InterfacePorts, error) {
	opts := qBridgeDefaultStaticOptions(
		map[string]string{
			"sysDescr": "1.3.6.1.2.1.1.1",
		},
		qBridgeIfTypesL2Basic,
	)
	opts.IfNameKey = ""
	opts.PostProcess = func(ports InterfacePorts, w map[string]map[string]string) error {
		mctOID := "1.3.6.1.4.1.171.11.116.2.2.7.8.1.3"
		mcuOID := "1.3.6.1.4.1.171.11.116.2.2.7.8.1.4"
		if strings.TrimSpace(w["sysDescr"]["0"]) == "DES-1210-52/ME/C1" {
			mctOID = "1.3.6.1.4.1.171.10.75.26.1.27.2.1.3"
			mcuOID = "1.3.6.1.4.1.171.10.75.26.1.27.2.1.4"
		}
		mct, err := c.Walk(mctOID, "")
		if err != nil {
			return err
		}
		mcu, err := c.Walk(mcuOID, "")
		if err != nil {
			return err
		}
		dlinkApplyMaskVLANsToPorts(ports, mct)
		dlinkApplyMaskVLANsToPorts(ports, mcu)
		return nil
	}
	return collectInterfacesQBridgeGeneric(c, opts)
}

func (d *dlinkIface2108) CollectInterfaces(c *Client) (InterfacePorts, error) {
	mib := "2"
	if d.newMIB {
		mib = "3"
	}
	prefix := "1.3.6.1.4.1.171.10.61." + mib
	w, err := walkMany(c, map[string]string{
		"ifName":      prefix + ".11.6.1.1",
		"ifAdminStat": "1.3.6.1.2.1.2.2.1.7",
		"egress":      prefix + ".13.1.1.3",
		"untagged":    prefix + ".13.1.1.4",
	}, "")
	if err != nil {
		return nil, err
	}
	pe := map[int][]string{}
	pu := map[int][]string{}
	for vidS, raw := range w["egress"] {
		vid, err := strconv.Atoi(strings.TrimSpace(vidS))
		if err != nil || vid <= 0 {
			continue
		}
		pe[vid] = bitmaskToArray(raw)
		pu[vid] = bitmaskToArray(w["untagged"][vidS])
	}
	ports := dlinkMergePortsFromMasks(w["ifName"], nil, w["ifAdminStat"], pe, pu, func(_, _ string) bool { return true })
	return ports, nil
}

func (*dlinkIface1100) CollectInterfaces(c *Client) (InterfacePorts, error) {
	w, err := walkMany(c, map[string]string{
		"ifAlias":      "1.3.6.1.2.1.31.1.1.1.18",
		"ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
		"ifType":       "1.3.6.1.2.1.2.2.1.3",
		"ifAdminStat":  "1.3.6.1.2.1.2.2.1.7",
	}, "")
	if err != nil {
		return nil, err
	}
	pe, pu, err := dlinkDGS1100VLANTables(c)
	if err != nil {
		return nil, err
	}
	ports := dlinkMergePortsFromMasks(w["ifOperStatus"], w["ifAlias"], w["ifAdminStat"], pe, pu, func(ifidx, oper string) bool {
		return strings.TrimSpace(oper) != "6" && strings.TrimSpace(w["ifType"][ifidx]) == "6"
	})
	return ports, nil
}

func dlinkMergePortsFromMasks(
	ifi map[string]string,
	ifa map[string]string,
	ifd map[string]string,
	pe map[int][]string,
	pu map[int][]string,
	keep func(ifidx, ifiVal string) bool,
) InterfacePorts {
	ports := InterfacePorts{}
	for ifidx, ifiVal := range ifi {
		if keep != nil && !keep(ifidx, ifiVal) {
			continue
		}
		n, _ := strconv.Atoi(ifidx)
		p := InterfacePort{
			VLANs:   map[int]int{},
			Name:    ifidx,
			IfIndex: n,
		}
		if ifa != nil {
			p.Descr = ifa[ifidx]
		}
		if ifd != nil && strings.TrimSpace(ifd[ifidx]) != "" && strings.TrimSpace(ifd[ifidx]) != "1" {
			p.Disabled = true
		}
		ports[ifidx] = p
	}
	for vid, eArr := range pe {
		uArr := pu[vid]
		for ifidx, p := range ports {
			i, err := strconv.Atoi(ifidx)
			if err != nil || i <= 0 {
				continue
			}
			pos := i - 1
			egress := pos < len(eArr) && eArr[pos] == "1"
			untag := pos < len(uArr) && uArr[pos] == "1"
			if egress && !untag {
				p.Tagged = true
			}
			if egress || untag {
				p.VLANs[vid] = 1
			}
			ports[ifidx] = p
		}
	}
	return ports
}

func dlinkDGS1100VLANTables(c *Client) (map[int][]string, map[int][]string, error) {
	e, err := c.Walk("1.3.6.1.4.1.171.10.134.1.1.7.6.1.4", "")
	if err != nil {
		return nil, nil, err
	}
	u, err := c.Walk("1.3.6.1.4.1.171.10.134.1.1.7.6.1.2", "")
	if err != nil {
		return nil, nil, err
	}
	pvid, err := c.Walk("1.3.6.1.4.1.171.10.134.1.1.7.7.1.1", "")
	if err != nil {
		return nil, nil, err
	}
	pe := map[int][]string{}
	pu := map[int][]string{}
	for key, raw := range e {
		vid := ifaceQBridgeCurrentVIDFromWalkKey(key)
		if vid <= 0 {
			continue
		}
		pe[vid] = bitmaskToArray(raw)
		pu[vid] = bitmaskToArray(u[key])
	}
	for vid, arr := range pe {
		want := strconv.Itoa(vid)
		for pkey, pval := range pvid {
			if strings.TrimSpace(pval) != want {
				continue
			}
			bp, err := strconv.Atoi(strings.TrimSpace(pkey))
			if err != nil || bp < 1 || bp > len(arr) {
				continue
			}
			arr[bp-1] = "1"
		}
	}
	return pe, pu, nil
}

func dlinkApplyMaskVLANsToPorts(ports InterfacePorts, m map[string]string) {
	for vidS, raw := range m {
		vid, err := strconv.Atoi(strings.TrimSpace(vidS))
		if err != nil || vid <= 0 {
			continue
		}
		for i, bit := range bitmaskToArray(raw) {
			if bit != "1" {
				continue
			}
			ifidx := strconv.Itoa(i + 1)
			if p, ok := ports[ifidx]; ok {
				p.VLANs[vid] = 1
				ports[ifidx] = p
			}
		}
	}
}

// enrich_3120_portnames: переименование ключей в формат "unit/port", если в стеке есть unit != 1.
func dlinkEnrich3120Portnames(c *Client, ports InterfacePorts) (InterfacePorts, bool, error) {
	ifd, err := c.Walk("1.3.6.1.2.1.2.2.1.2", "")
	if err != nil {
		return nil, false, err
	}
	re := regexp.MustCompile(`Port (\d+) on Unit (\d+)`)
	haveUnits := false
	out := InterfacePorts{}
	for ifi, p := range ports {
		pname := ifi
		if d, ok := ifd[ifi]; ok {
			if mm := re.FindStringSubmatch(d); len(mm) == 3 {
				pname = mm[2] + "/" + mm[1]
				if mm[2] != "1" {
					haveUnits = true
				}
			}
		}
		cp := p
		cp.Name = pname
		out[pname] = cp
	}
	if !haveUnits {
		return ports, false, nil
	}
	return out, true, nil
}

// enrich_3120_ism: добавление VLAN из ism-маски к портам по полю ifindex.
func dlinkEnrich3120ISM(c *Client, ports InterfacePorts) error {
	ism, err := c.Walk("1.3.6.1.4.1.171.12.64.3.1.1.4", "")
	if err != nil {
		return err
	}
	for vidS, raw := range ism {
		vid, err := strconv.Atoi(strings.TrimSpace(vidS))
		if err != nil || vid <= 0 {
			continue
		}
		mask := bitmaskToArray(raw)
		for key, p := range ports {
			ifidx := p.IfIndex
			if ifidx <= 0 {
				continue
			}
			if ifidx <= 0 || ifidx > len(mask) || mask[ifidx-1] != "1" {
				continue
			}
			p.VLANs[vid] = 1
			ports[key] = p
		}
	}
	return nil
}
