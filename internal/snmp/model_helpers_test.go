package snmp

import (
	"errors"
	"reflect"
	"testing"
)

func TestBitmaskToArrayWithBEF(t *testing.T) {
	// 0x03 = 00000011, направление разворота тут принципиально.
	gotMSB := bitmaskToArrayWithBEF("\x03", false)
	wantMSB := []string{"0", "0", "0", "0", "0", "0", "1", "1"}
	if !reflect.DeepEqual(gotMSB, wantMSB) {
		t.Fatalf("MSB order mismatch: got=%v want=%v", gotMSB, wantMSB)
	}

	gotLSB := bitmaskToArrayWithBEF("\x03", true)
	wantLSB := []string{"1", "1", "0", "0", "0", "0", "0", "0"}
	if !reflect.DeepEqual(gotLSB, wantLSB) {
		t.Fatalf("LSB order mismatch: got=%v want=%v", gotLSB, wantLSB)
	}
}

func TestShortPortName(t *testing.T) {
	cases := map[string]string{
		"FastEthernet0/1":       "Fa0/1",
		"TenGigabitEthernet1/1": "Te1/1",
		"GigabitEthernet0/24":   "Gi0/24",
		"Port-channel10":        "Po10",
		"Ethernet1":             "Ethernet1",
	}
	for in, want := range cases {
		if got := shortPortName(in); got != want {
			t.Fatalf("shortPortName(%q)=%q want=%q", in, got, want)
		}
	}
}

func TestParseCiscoXConnect(t *testing.T) {
	in := map[string]string{
		"1": "GigabitEthernet0/1.100",
		"2": "Te1/1/1.200",
		"3": "bad-value",
		"4": "Loopback0.10",
	}
	got := parseCiscoXConnect(in)
	want := map[string][]int{
		"Gi0/1":   {100},
		"Te1/1/1": {200},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCiscoXConnect mismatch: got=%v want=%v", got, want)
	}
}

func TestMergeIfaceOIDMaps(t *testing.T) {
	got := mergeIfaceOIDMaps(
		map[string]string{"a": "1", "b": "2"},
		map[string]string{"b": "22", "c": "3"},
	)
	want := map[string]string{"a": "1", "b": "22", "c": "3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeIfaceOIDMaps mismatch: got=%v want=%v", got, want)
	}
}

func TestIfaceQBridgeCurrentVIDFromWalkKey(t *testing.T) {
	cases := map[string]int{
		"5":         5,
		"123.456":   456,
		" vlan 20 ": 0,
		"abc":       0,
		"0":         0,
	}
	for in, want := range cases {
		if got := ifaceQBridgeCurrentVIDFromWalkKey(in); got != want {
			t.Fatalf("ifaceQBridgeCurrentVIDFromWalkKey(%q)=%d want=%d", in, got, want)
		}
	}
}

func TestIfaceQBridgeRawVLANTablesAppliesPVID(t *testing.T) {
	pe, pu := ifaceQBridgeRawVLANTables(
		map[string]string{"100": "\x80"}, // port1 egress
		map[string]string{"100": "\x00"},
		map[string]string{"2": "100"}, // pvid should force port2 egress bit
		false,
	)

	wantE := []string{"1", "1", "0", "0", "0", "0", "0", "0"}
	wantU := []string{"0", "0", "0", "0", "0", "0", "0", "0"}
	if !reflect.DeepEqual(pe[100], wantE) {
		t.Fatalf("egress mismatch: got=%v want=%v", pe[100], wantE)
	}
	if !reflect.DeepEqual(pu[100], wantU) {
		t.Fatalf("untag mismatch: got=%v want=%v", pu[100], wantU)
	}
}

func TestParseJuniperBridgePortList(t *testing.T) {
	if got := parseJuniperBridgePortList("1, 2,3"); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("valid parse mismatch: %v", got)
	}
	if got := parseJuniperBridgePortList("x,2,3"); got != nil {
		t.Fatalf("expected nil for invalid list, got %v", got)
	}
}

func TestApplyJuniperStaticEgressVLANs(t *testing.T) {
	ports := InterfacePorts{
		"10": {VLANs: map[int]int{}},
	}
	applyJuniperStaticEgressVLANs(ports, map[string]map[int]struct{}{
		"10": {100: {}, 200: {}},
	})
	if !ports["10"].Tagged {
		t.Fatalf("tag flag not set")
	}
	gotVLAN := ports["10"].VLANs
	wantVLAN := map[int]int{100: 1, 200: 1}
	if !reflect.DeepEqual(gotVLAN, wantVLAN) {
		t.Fatalf("vlan map mismatch: got=%v want=%v", gotVLAN, wantVLAN)
	}
}

func TestARPHelpers(t *testing.T) {
	joined := joinARPToVLAN(
		map[string]string{
			"10.192.0.2.1": "aa:bb",
			"bad":          "xx",
		},
		map[string]string{"10": "100"},
	)
	wantJoined := map[string]map[string]string{"100": {"192.0.2.1": "aa:bb"}}
	if !reflect.DeepEqual(joined, wantJoined) {
		t.Fatalf("joinARPToVLAN mismatch: got=%v want=%v", joined, wantJoined)
	}

	ivQ := ifindexToVLANQBridge(
		map[string]string{"1": "Vlanif100", "2": "irb.200"},
		map[string]string{"100": "Vlanif100"},
	)
	if !reflect.DeepEqual(ivQ, map[string]string{"1": "100"}) {
		t.Fatalf("ifindexToVLANQBridge mismatch: %v", ivQ)
	}

	ivH := ifindexToVLANHuaweiVlanif(map[string]string{"1": "Vlanif10", "2": "xe-0/0/1"})
	if !reflect.DeepEqual(ivH, map[string]string{"1": "10"}) {
		t.Fatalf("ifindexToVLANHuaweiVlanif mismatch: %v", ivH)
	}
}

func TestIfindexToVLANJuniper(t *testing.T) {
	got := ifindexToVLANJuniper(map[string]string{
		"1": "irb.664",
		"2": "xe-0/1/2.1000",
		"3": "ge-0/0/1.0",
	})
	want := map[string]string{"1": "664", "2": "1000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ifindexToVLANJuniper mismatch: got=%v want=%v", got, want)
	}
}

func TestDecodeCiscoVRFNameFromOIDPrefix(t *testing.T) {
	got := decodeCiscoVRFNameFromOIDPrefix("114.101.100")
	if got != "red" {
		t.Fatalf("decodeCiscoVRFNameFromOIDPrefix mismatch: got=%q want=%q", got, "red")
	}
}

func TestDLinkHelpers(t *testing.T) {
	if dlink1210MIBSuffixByType(11) != "75.14.1" {
		t.Fatalf("unexpected suffix for typ=11")
	}
	if dlink1210MIBSuffixByType(999) != "75.5" {
		t.Fatalf("unexpected suffix fallback")
	}

	ports := dlinkMergePortsFromMasks(
		map[string]string{"1": "up", "2": "up"},
		map[string]string{"1": "p1", "2": "p2"},
		map[string]string{"1": "1", "2": "2"},
		map[int][]string{100: {"1", "1"}},
		map[int][]string{100: {"1", "0"}},
		nil,
	)
	if !ports["2"].Tagged {
		t.Fatalf("expected port2 to be tagged")
	}
	if !ports["2"].Disabled {
		t.Fatalf("expected port2 disabled flag")
	}

	dlinkApplyMaskVLANsToPorts(ports, map[string]string{"200": "\x80"})
	if ports["1"].VLANs[200] != 1 {
		t.Fatalf("expected vlan 200 added from mask")
	}
}

func TestFormatExtremeMAC(t *testing.T) {
	if got, ok := formatExtremeMAC("\x01\x02\x03\x04\x05\x06"); !ok || got != "01:02:03:04:05:06" {
		t.Fatalf("binary mac format mismatch: got=%q ok=%v", got, ok)
	}
	if got, ok := formatExtremeMAC("0a-0b-0c-0d-0e-0f"); !ok || got != "0a:0b:0c:0d:0e:0f" {
		t.Fatalf("hex mac format mismatch: got=%q ok=%v", got, ok)
	}
	if _, ok := formatExtremeMAC("zz"); ok {
		t.Fatalf("expected invalid mac to fail")
	}
}

type testBaseCollector struct {
	ret InterfacePorts
	err error
}

func (b testBaseCollector) CollectInterfaces(*Client) (InterfacePorts, error) {
	return b.ret, b.err
}

type testEnricher struct {
	err error
}

func (e testEnricher) EnrichInterfaces(_ *Client, ports InterfacePorts) error {
	if e.err != nil {
		return e.err
	}
	ports["enriched"] = InterfacePort{Name: "enriched"}
	return nil
}

func TestIfaceCollectorWithEnrich(t *testing.T) {
	if got := NewIfaceCollectorWithEnrich(nil); got != nil {
		t.Fatalf("nil base should produce nil wrapper")
	}

	base := testBaseCollector{ret: InterfacePorts{"1": {Name: "ok"}}}
	wrapped := NewIfaceCollectorWithEnrich(base, testEnricher{})
	out, err := wrapped.CollectInterfaces(&Client{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := out["enriched"]; !ok {
		t.Fatalf("expected enriched marker in output")
	}

	wrappedErr := NewIfaceCollectorWithEnrich(base, testEnricher{err: errors.New("boom")})
	if _, err := wrappedErr.CollectInterfaces(&Client{}); err == nil {
		t.Fatalf("expected error from enricher")
	}
}
