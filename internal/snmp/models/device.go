package models

import "go-collector/internal/snmp"

// Device is a generic model wrapper over vendor collectors.
type Device struct {
	client       *snmp.Client
	ifaceCollect snmp.VendorIfaceCollector
	arpCollect   snmp.VendorARPCollector
	macCollect   snmp.VendorMACCollector
}

func (m *Device) CollectInterfaces() (map[string]any, error) {
	return m.ifaceCollect.CollectInterfaces(m.client)
}

func (m *Device) CollectARP() (map[string]map[string]string, error) {
	return m.arpCollect.CollectARP(m.client)
}

func (m *Device) CollectMAC(ctx *snmp.MacDbContext) (map[string]any, error) {
	return m.macCollect.CollectMAC(m.client, ctx)
}
