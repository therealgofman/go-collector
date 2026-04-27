package models

import (
	"reflect"
	"testing"

	"go-collector/internal/snmp"
)

type ifaceCollectorStub struct {
	gotClient *snmp.Client
	ret       snmp.InterfacePorts
	err       error
}

func (s *ifaceCollectorStub) CollectInterfaces(c *snmp.Client) (snmp.InterfacePorts, error) {
	s.gotClient = c
	return s.ret, s.err
}

type arpCollectorStub struct {
	gotClient *snmp.Client
	ret       map[string]map[string]string
	err       error
}

func (s *arpCollectorStub) CollectARP(c *snmp.Client) (map[string]map[string]string, error) {
	s.gotClient = c
	return s.ret, s.err
}

type macCollectorStub struct {
	gotClient *snmp.Client
	gotCtx    *snmp.MacDbContext
	ret       snmp.MACTable
	err       error
}

func (s *macCollectorStub) CollectMAC(c *snmp.Client, ctx *snmp.MacDbContext) (snmp.MACTable, error) {
	s.gotClient = c
	s.gotCtx = ctx
	return s.ret, s.err
}

func TestDeviceCollectInterfacesDelegatesToCollector(t *testing.T) {
	client := &snmp.Client{}
	expected := snmp.InterfacePorts{
		"1": {Name: "Gi1/0/1", VLANs: map[int]int{}, Extra: map[string]string{}, Persist: []snmp.PortPersistOp{}},
	}
	ifaceStub := &ifaceCollectorStub{ret: expected}

	m := &Device{
		client:       client,
		ifaceCollect: ifaceStub,
	}

	got, err := m.CollectInterfaces()
	if err != nil {
		t.Fatalf("CollectInterfaces() returned unexpected error: %v", err)
	}
	if ifaceStub.gotClient != client {
		t.Fatalf("collector received unexpected client pointer")
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("CollectInterfaces() result mismatch: got=%v want=%v", got, expected)
	}
}

func TestDeviceCollectARPDelegatesToCollector(t *testing.T) {
	client := &snmp.Client{}
	expected := map[string]map[string]string{
		"100": {"10.0.0.1": "aa:bb:cc:dd:ee:ff"},
	}
	arpStub := &arpCollectorStub{ret: expected}

	m := &Device{
		client:     client,
		arpCollect: arpStub,
	}

	got, err := m.CollectARP()
	if err != nil {
		t.Fatalf("CollectARP() returned unexpected error: %v", err)
	}
	if arpStub.gotClient != client {
		t.Fatalf("collector received unexpected client pointer")
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("CollectARP() result mismatch: got=%v want=%v", got, expected)
	}
}

func TestDeviceCollectMACDelegatesToCollector(t *testing.T) {
	client := &snmp.Client{}
	ctx := &snmp.MacDbContext{
		IfIndexToPortID: map[int]int{10: 1010},
	}
	expected := snmp.MACTable{Format: snmp.MacTableFormatFDB, Entries: []snmp.MACEntry{}}
	macStub := &macCollectorStub{ret: expected}

	m := &Device{
		client:     client,
		macCollect: macStub,
	}

	got, err := m.CollectMAC(ctx)
	if err != nil {
		t.Fatalf("CollectMAC() returned unexpected error: %v", err)
	}
	if macStub.gotClient != client {
		t.Fatalf("collector received unexpected client pointer")
	}
	if macStub.gotCtx != ctx {
		t.Fatalf("collector received unexpected context pointer")
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("CollectMAC() result mismatch: got=%v want=%v", got, expected)
	}
}
