package models

import "go-collector/internal/snmp"

// Device is a generic model wrapper over vendor collectors.
type Device struct {
	client       *snmp.Client
	ifaceCollect snmp.VendorIfaceCollector
	arpCollect   snmp.VendorARPCollector
	macCollect   snmp.VendorMACCollector
}

func (m *Device) CollectInterfaces() (snmp.InterfacePorts, error) {
	return m.ifaceCollect.CollectInterfaces(m.client)
}

func (m *Device) CollectARP() (snmp.ARPTable, error) {
	return m.arpCollect.CollectARP(m.client)
}

// IsArpNoop возвращает true, когда для модели используется no-op ARP коллектор.
func (m *Device) IsArpNoop() bool {
	type arpNoop interface {
		IsNoop() bool
	}
	v, ok := m.arpCollect.(arpNoop)
	return ok && v.IsNoop()
}

func (m *Device) CollectMAC(ctx *snmp.MacDbContext) (snmp.MACTable, error) {
	return m.macCollect.CollectMAC(m.client, ctx)
}
