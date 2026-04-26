package snmp

import (
	"regexp"
)

// qBridgeARPHooks — точка расширения для построения карты ifIndex→номер VLAN перед склейкой с ARP (у Huawei — Vlanif).
type qBridgeARPHooks interface {
	MergeIfIndexToVLANForARP(ivQBridge map[string]string, ifName map[string]string, dot1qVlanStaticName map[string]string) map[string]string
}

// joinARPToVLAN сопоставляет суффиксы OID ARP "<ifIndex>.<ip>" с номером VLAN из iv и группирует по VLAN → IP → MAC.
func joinARPToVLAN(arp map[string]string, iv map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{}
	re := regexp.MustCompile(`^(\d+)\.(\d+\.\d+\.\d+\.\d+)$`)
	for k, mac := range arp {
		m := re.FindStringSubmatch(k)
		if len(m) != 3 {
			continue
		}
		ifidx, ip := m[1], m[2]
		vlan, ok := iv[ifidx]
		if !ok {
			continue
		}
		if _, ok := out[vlan]; !ok {
			out[vlan] = map[string]string{}
		}
		out[vlan][ip] = mac
	}
	return out
}

// ifindexToVLANQBridge строит ifIndex → VLAN ID по точному совпадению staticName из dot1q с ifName.
func ifindexToVLANQBridge(ifName map[string]string, dot1qVlanStaticName map[string]string) map[string]string {
	nameToIfIndex := map[string]string{}
	for ifidx, name := range ifName {
		nameToIfIndex[name] = ifidx
	}
	iv := map[string]string{}
	for vlanKey, staticName := range dot1qVlanStaticName {
		if ifidx, ok := nameToIfIndex[staticName]; ok {
			iv[ifidx] = vlanKey
		}
	}
	return iv
}

// ifindexToVLANHuaweiVlanif добавляет соответствия для интерфейсов Vlanif<N> → N.
func ifindexToVLANHuaweiVlanif(ifName map[string]string) map[string]string {
	iv := map[string]string{}
	vif := regexp.MustCompile(`(?i)Vlanif(\d+)`)
	for ifidx, name := range ifName {
		mm := vif.FindStringSubmatch(name)
		if len(mm) == 2 {
			iv[ifidx] = mm[1]
		}
	}
	return iv
}

// MergeIfIndexToVLANForARPHuawei объединяет карту Q-BRIDGE с картой Vlanif (приоритет дублей — последняя запись Vlanif).
func MergeIfIndexToVLANForARPHuawei(ivQBridge map[string]string, ifName map[string]string) map[string]string {
	ivVlanif := ifindexToVLANHuaweiVlanif(ifName)
	merged := map[string]string{}
	for k, v := range ivQBridge {
		merged[k] = v
	}
	for k, v := range ivVlanif {
		merged[k] = v
	}
	return merged
}
