package snmp

import "testing"

type qbridgeHooksStub struct{}

func (qbridgeHooksStub) MergeIfIndexToVLANForARP(ivQBridge map[string]string, ifName map[string]string, dot1qVlanStaticName map[string]string) map[string]string {
	return ivQBridge
}

func TestQBridgeMACCollectMACRequiresContext(t *testing.T) {
	c := &Client{}
	m := &qbridgeMAC{fdbWalkUsesGetBulk: true}

	got, err := m.CollectMAC(c, nil)
	if err == nil {
		t.Fatalf("expected error for nil context, got result=%v", got)
	}
	if err.Error() != "mac_db_context is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJuniperQBridgeMACCollectMACRequiresContext(t *testing.T) {
	c := &Client{}
	m := &juniperQBridgeMAC{fdbWalkUsesGetBulk: true}

	got, err := m.CollectMAC(c, nil)
	if err == nil {
		t.Fatalf("expected error for nil context, got result=%v", got)
	}
	if err.Error() != "mac_db_context is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtremePrivateMACCollectMACRequiresContext(t *testing.T) {
	c := &Client{}
	m := &extremePrivateMAC{useBulkWalk: false}

	got, err := m.CollectMAC(c, nil)
	if err == nil {
		t.Fatalf("expected error for nil context, got result=%v", got)
	}
	if err.Error() != "mac_db_context is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtremeXSeriesMACCollectMACRequiresContext(t *testing.T) {
	c := &Client{}
	m := &extremeXSeriesMAC{useBulkWalk: true}

	got, err := m.CollectMAC(c, nil)
	if err == nil {
		t.Fatalf("expected error for nil context, got result=%v", got)
	}
	if err.Error() != "mac_db_context is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBridgeMIBMACCollectMACRequiresContext(t *testing.T) {
	c := &Client{}
	m := &bridgeMIBMAC{
		fdbIdxCommunity:    true,
		fdbWalkUsesGetBulk: false,
	}

	got, err := m.CollectMAC(c, nil)
	if err == nil {
		t.Fatalf("expected error for nil context, got result=%v", got)
	}
	if err.Error() != "mac_db_context is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoopARPCollectorImplementation(t *testing.T) {
	c := &Client{}
	m := &noopARPCollector{}

	got, err := m.CollectARP(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Fatalf("expected empty map, got=%v", got)
	}
}

func TestHuaweiARPQBridgeAliasImplementation(t *testing.T) {
	hooks := qbridgeHooksStub{}
	collector := NewHuaweiARPQBridge(hooks)
	mainCollector, ok := collector.(*qbridgeMainARP)
	if !ok {
		t.Fatalf("expected *qbridgeMainARP, got %T", collector)
	}
	if mainCollector.hooks == nil {
		t.Fatalf("expected hooks to be set in qbridgeMainARP")
	}
}
