// Package models — конкретные устройства (vendor_model) и фабрика CreateModel; зависит от snmp (OID/стратегии), snmp не импортирует models.
package models

import "go-collector/internal/snmp"

// CreateModel — единственная точка выбора класса по правилам YAML; инициализация полей модели.
func CreateModel(ip, comm string, rules []snmp.ModelRule, debug bool, timeout float64, retries int, oidTiming bool, getBulkMaxRepetitions int) (snmp.Model, snmp.DeviceIdentity, string) {
	c := snmp.New(ip, comm, timeout, retries, debug, oidTiming, getBulkMaxRepetitions)
	id := c.Identity()
	if id.Error != "" {
		return nil, id, id.Error
	}
	mid := snmp.ResolveModelID(id, rules)
	if mid == "" {
		return nil, id, "unknown_model"
	}
	switch mid {
	case "cisco_catalyst_4500":
		m := &Device{client: c}
		m.ifaceCollect = snmp.NewIfaceCollectorWithEnrich(
			snmp.NewCiscoIfaceL2(),
		)
		m.arpCollect = snmp.NewCiscoVlanARP()
		m.macCollect = snmp.NewBridgeMIBMAC(true, false)
		return m, id, ""
	case "huawei_cloud_engine_s6330", "huawei_cloud_engine_s6750h":
		m := &Device{client: c}
		m.ifaceCollect = snmp.NewHuaweiIfaceHWL2(snmp.HuaweiCloudEngineInterfaceNameKeep)
		m.arpCollect = snmp.NewQBridgeMainARP(HuaweiARPHooks{})
		m.macCollect = snmp.NewBridgeMIBMAC(false, true)
		return m, id, ""
	case "juniper_mx_204", "juniper_qfx5110":
		m := &Device{client: c}
		m.ifaceCollect = snmp.NewJuniperIfaceQBridgeStatic()
		m.arpCollect = snmp.NewJuniperARP()
		m.macCollect = snmp.NewJuniperQBridgeMAC(true)
		return m, id, ""
	case "dlink_des_1218_me":
		m := &Device{client: c}
		m.ifaceCollect = snmp.NewDLinkIface3028()
		m.arpCollect = snmp.NewNoopARP()
		m.macCollect = snmp.NewQBridgeMAC(true)
		return m, id, ""
	case "snr":
		m := &Device{client: c}
		m.ifaceCollect = snmp.NewSNRIface()
		m.arpCollect = snmp.NewNoopARP()
		m.macCollect = snmp.NewBridgeMIBMAC(false, true)
		return m, id, ""
	case "snr_qbridge":
		m := &Device{client: c}
		m.ifaceCollect = snmp.NewQBridgeIfaceCurrentDefault(snmp.QBridgeIfTypesL2StackLike())
		m.arpCollect = snmp.NewNoopARP()
		m.macCollect = snmp.NewBridgeMIBMAC(false, true)
		return m, id, ""
	case "extreme_xseries":
		m := &Device{client: c}
		m.ifaceCollect = snmp.NewExtremeXSeriesIface()
		m.arpCollect = snmp.NewExtremeXSeriesARP()
		m.macCollect = snmp.NewExtremeXSeriesMAC(false)
		return m, id, ""
	case "hpe_5900":
		m := &Device{client: c}
		m.ifaceCollect = snmp.NewHPE5900IfaceQBridgeStatic()
		m.arpCollect = snmp.NewNoopARP()
		m.macCollect = snmp.NewBridgeMIBMAC(false, true)
		return m, id, ""
	default:
		return nil, id, "no_class_registered:" + mid
	}
}
