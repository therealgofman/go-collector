package persist

import (
	"strings"
	"testing"

	"go-collector/internal/snmp"
)

func TestBuildFallbackCountersWarning(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		got := buildFallbackCountersWarning("switch_id=1, ip=10.0.0.1", map[int]map[int]int{})
		if got != "" {
			t.Fatalf("expected empty warning, got %q", got)
		}
	})

	t.Run("renders sorted vlan sections", func(t *testing.T) {
		got := buildFallbackCountersWarning("switch_id=1, ip=10.0.0.1", map[int]map[int]int{
			200: {11: 1},
			100: {12: 3},
		})
		if !strings.Contains(got, "fallback VLAN counters from collector") {
			t.Fatalf("expected fallback header in warning, got %q", got)
		}
		first := strings.Index(got, "vlan=100")
		second := strings.Index(got, "vlan=200")
		if first < 0 || second < 0 || first > second {
			t.Fatalf("expected sorted VLAN sections, got %q", got)
		}
	})
}

func TestPrepareMACRows(t *testing.T) {
	svc := &Service{}
	hostCtx := "switch_id=10, ip=10.10.10.10"
	pr := snmp.PollResult{
		Switch: snmp.SwitchRow{
			DomainID: "dom-1",
		},
		MacTable: snmp.MACTable{
			Entries: []snmp.MACEntry{
				{PortID: 0, VLANID: 5, MAC: "00:11:22:33:44:55", Status: 3},  // no port_id
				{PortID: 7, VLANID: 0, VLAN: 0, MAC: "00:11:22:33:44:55"},    // no vlan_id/vlan
				{PortID: 7, VLANID: 0, VLAN: 9999, MAC: "00:11:22:33:44:55"}, // fallback sentinel
				{PortID: 7, VLANID: 0, VLAN: 777, MAC: "00:11:22:33:44:55"},  // unresolved VLAN
				{PortID: 8, VLANID: 0, VLAN: 10, MAC: "00:11:22:33:44:55"},   // resolved via local
				{PortID: 9, VLANID: 20, MAC: "invalid-mac"},                  // bad MAC
				{PortID: 9, VLANID: 20, MAC: "00:11:22:aa:bb:cc", Status: 5}, // valid row
			},
		},
	}
	local := map[string]map[int]int{
		"dom-1": {10: 1010},
	}
	global := map[int]int{
		20: 2020,
	}

	prepared, warnings := svc.prepareMACRows(hostCtx, pr, local, global)
	if len(prepared) != 2 {
		t.Fatalf("expected 2 prepared rows, got %d", len(prepared))
	}
	if prepared[0].portID != 8 || prepared[0].vlanID != 1010 {
		t.Fatalf("unexpected first prepared row: %+v", prepared[0])
	}
	if prepared[1].portID != 9 || prepared[1].vlanID != 20 {
		t.Fatalf("unexpected second prepared row: %+v", prepared[1])
	}

	if len(warnings) != 4 {
		t.Fatalf("expected 4 warnings, got %d: %#v", len(warnings), warnings)
	}
	assertWarningsContain(t, warnings, "no port_id")
	assertWarningsContain(t, warnings, "no vlan_id/vlan")
	assertWarningsContain(t, warnings, "VLAN не найден в справочнике БД")
	assertWarningsContain(t, warnings, "invalid mac")
}

func assertWarningsContain(t *testing.T, warnings []string, want string) {
	t.Helper()
	for _, w := range warnings {
		if strings.Contains(w, want) {
			return
		}
	}
	t.Fatalf("expected warning containing %q in %#v", want, warnings)
}
