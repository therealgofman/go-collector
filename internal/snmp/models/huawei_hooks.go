package models

import "go-collector/internal/snmp"

// HuaweiARPHooks расширяет Q-BRIDGE VLAN mapping с Vlanif<N>.
type HuaweiARPHooks struct{}

// MergeIfIndexToVLANForARP объединяет карту Q-BRIDGE с картой Vlanif (приоритет дублей — последняя запись Vlanif).
func (HuaweiARPHooks) MergeIfIndexToVLANForARP(ivQBridge map[string]string, ifName map[string]string, dot1qVlanStaticName map[string]string) map[string]string {
	_ = dot1qVlanStaticName
	return snmp.MergeIfIndexToVLANForARPHuawei(ivQBridge, ifName)
}
