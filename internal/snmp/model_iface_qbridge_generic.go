package snmp

import (
	"strconv"
	"strings"
)

// -------------------------------- aka get_qbridge_vlan_table --------------------------------
// qBridgeGenericOptions задаёт универсальный конвейер сбора интерфейсов по Q-BRIDGE-MIB.
//
// Идея:
//  1. Собрать единый набор таблиц (ifType/ifAdmin/ifAlias/ifName + Q-BRIDGE egress/untagged/pvid).
//  2. Декодировать VLAN-маски единообразно (QBridgeRawVLANTables).
//  3. Применить vendor/model-specific hooks только там, где это действительно нужно:
//     - PositionByIfIndex: как вычислить позицию порта в битовой маске VLAN.
//     - PortKey: как именовать ключ порта в результате (ifIndex или ifName).
//     - PostProcess: дополнительные шаги после базового слияния.
//
// Такой контракт позволяет разным вендорам (Huawei, D-Link, Extreme и др.) переиспользовать
// одно ядро без копирования общей логики Q-BRIDGE.
type qBridgeGenericOptions struct {
	OIDs map[string]string

	EgressKey   string
	UntaggedKey string
	PvidKey     string
	BitmaskBEF  bool

	IfTypeKey        string
	IfAdminStatusKey string
	IfAliasKey       string
	IfNameKey        string
	AllowedIfTypes   map[string]struct{}

	// PositionByIfIndex возвращает индекс (0-based) в маске VLAN для данного ifIndex.
	// Если nil, используется дефолт: position = ifIndex - 1.
	PositionByIfIndex func(ifidx string, w map[string]map[string]string) (int, bool)
	// PortKey вычисляет ключ порта в выходном map (по умолчанию ifIndex).
	PortKey func(ifidx string, p map[string]any, w map[string]map[string]string) string
	// PostProcess выполняется после базового merge (например, vendor-specific enrich).
	PostProcess func(ports map[string]map[string]any, w map[string]map[string]string) error
}

type qBridgeGenericCollector struct {
	opts qBridgeGenericOptions
}

func (q *qBridgeGenericCollector) CollectInterfaces(c *Client) (map[string]any, error) {
	return collectInterfacesQBridgeGeneric(c, q.opts)
}

var qBridgeBaseIfOIDs = map[string]string{
	"ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
	"ifAlias":       "1.3.6.1.2.1.31.1.1.1.18",
	"ifType":        "1.3.6.1.2.1.2.2.1.3",
	"ifName":        "1.3.6.1.2.1.31.1.1.1.1",
}

var (
	// Фильтр интерфейсов для L2/Q-BRIDGE: оставляем только ethernet-порты и (опционально) LAG,
	// чтобы не тащить виртуальные/служебные интерфейсы в VLAN enrichment.
	// ifType по IANAifType-MIB:
	//   6   = ethernetCsmacd
	//   62  = fastEther (legacy/obsolete, но встречается на старых устройствах)
	//   117 = gigabitEthernet (legacy/obsolete, но встречается на старых устройствах)
	//   161 = ieee8023adLag (порт-канал/LAG; используется в stack-like профилях)
	qBridgeIfTypesL2Basic     = map[string]struct{}{"6": {}, "117": {}}
	qBridgeIfTypesL2Extended  = map[string]struct{}{"6": {}, "62": {}, "117": {}}
	qBridgeIfTypesL2StackLike = map[string]struct{}{"6": {}, "62": {}, "117": {}, "161": {}}
)

// QBridgeIfTypesL2StackLike возвращает копию набора ifType (6,62,117,161).
func QBridgeIfTypesL2StackLike() map[string]struct{} {
	return cloneStringSet(qBridgeIfTypesL2StackLike)
}

func cloneStringSet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

func qBridgeDefaultCurrentOptions(extraOIDs map[string]string, allowedIfTypes map[string]struct{}) qBridgeGenericOptions {
	oids := mergeIfaceOIDMaps(ifaceQBridgeCurrentOIDs, qBridgeBaseIfOIDs)
	if len(extraOIDs) > 0 {
		oids = mergeIfaceOIDMaps(oids, extraOIDs)
	}
	return qBridgeGenericOptions{
		OIDs:             oids,
		EgressKey:        "dot1qVlanCurrentEgressPorts",
		UntaggedKey:      "dot1qVlanCurrentUntaggedPorts",
		PvidKey:          "dot1qPvid",
		IfTypeKey:        "ifType",
		IfAdminStatusKey: "ifAdminStatus",
		IfAliasKey:       "ifAlias",
		IfNameKey:        "ifName",
		AllowedIfTypes:   cloneStringSet(allowedIfTypes),
	}
}

func qBridgeDefaultStaticOptions(extraOIDs map[string]string, allowedIfTypes map[string]struct{}) qBridgeGenericOptions {
	oids := mergeIfaceOIDMaps(ifaceQBridgeStaticOIDs, qBridgeBaseIfOIDs)
	if len(extraOIDs) > 0 {
		oids = mergeIfaceOIDMaps(oids, extraOIDs)
	}
	return qBridgeGenericOptions{
		OIDs:             oids,
		EgressKey:        "dot1qVlanStaticEgressPorts",
		UntaggedKey:      "dot1qVlanStaticUntaggedPorts",
		PvidKey:          "dot1qPvid",
		IfTypeKey:        "ifType",
		IfAdminStatusKey: "ifAdminStatus",
		IfAliasKey:       "ifAlias",
		IfNameKey:        "ifName",
		AllowedIfTypes:   cloneStringSet(allowedIfTypes),
	}
}

// NewQBridgeIfaceCurrentDefault создаёт универсальный collector для Q-BRIDGE current таблиц.
// Использует стандартные IF-MIB OID и переданный whitelist ifType.
func NewQBridgeIfaceCurrentDefault(allowedIfTypes map[string]struct{}) VendorIfaceCollector {
	return &qBridgeGenericCollector{
		opts: qBridgeDefaultCurrentOptions(nil, allowedIfTypes),
	}
}

// NewQBridgeIfaceStaticDefault создаёт универсальный collector для Q-BRIDGE static таблиц.
// Использует стандартные IF-MIB OID и переданный whitelist ifType.
func NewQBridgeIfaceStaticDefault(allowedIfTypes map[string]struct{}) VendorIfaceCollector {
	return &qBridgeGenericCollector{
		opts: qBridgeDefaultStaticOptions(nil, allowedIfTypes),
	}
}

func collectInterfacesQBridgeGeneric(c *Client, opts qBridgeGenericOptions) (map[string]any, error) {
	w, err := walkMany(c, opts.OIDs, "")
	if err != nil {
		return nil, err
	}

	pe, pu := ifaceQBridgeRawVLANTables(
		w[opts.EgressKey],
		w[opts.UntaggedKey],
		w[opts.PvidKey],
		opts.BitmaskBEF,
	)

	ports := map[string]map[string]any{}
	for ifidx, typRaw := range w[opts.IfTypeKey] {
		typ := strings.TrimSpace(typRaw)
		if len(opts.AllowedIfTypes) > 0 {
			if _, ok := opts.AllowedIfTypes[typ]; !ok {
				continue
			}
		}
		n, err := strconv.Atoi(strings.TrimSpace(ifidx))
		if err != nil || n <= 0 {
			continue
		}
		name := ifidx
		if opts.IfNameKey != "" {
			if v := strings.TrimSpace(w[opts.IfNameKey][ifidx]); v != "" {
				name = v
			}
		}
		p := map[string]any{
			"vlan":    map[int]int{},
			"name":    name,
			"ifindex": n,
		}
		if opts.IfAliasKey != "" {
			p["descr"] = w[opts.IfAliasKey][ifidx]
		}
		if opts.IfAdminStatusKey != "" {
			if strings.TrimSpace(w[opts.IfAdminStatusKey][ifidx]) != "" && strings.TrimSpace(w[opts.IfAdminStatusKey][ifidx]) != "1" {
				p["disab"] = 1
			}
		}
		ports[ifidx] = p
	}

	defaultPos := func(ifidx string, _ map[string]map[string]string) (int, bool) {
		n, err := strconv.Atoi(strings.TrimSpace(ifidx))
		if err != nil || n <= 0 {
			return 0, false
		}
		return n - 1, true
	}
	posFn := opts.PositionByIfIndex
	if posFn == nil {
		posFn = defaultPos
	}

	for vid, eArr := range pe {
		uArr := pu[vid]
		for ifidx, p := range ports {
			pos, ok := posFn(ifidx, w)
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

	if opts.PostProcess != nil {
		if err := opts.PostProcess(ports, w); err != nil {
			return nil, err
		}
	}

	portKeyFn := opts.PortKey
	if portKeyFn == nil {
		portKeyFn = func(ifidx string, _ map[string]any, _ map[string]map[string]string) string { return ifidx }
	}
	out := map[string]any{}
	for ifidx, p := range ports {
		k := portKeyFn(ifidx, p, w)
		if strings.TrimSpace(k) == "" {
			k = ifidx
		}
		out[k] = p
	}
	return out, nil
}
