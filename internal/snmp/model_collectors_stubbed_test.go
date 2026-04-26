package snmp

import (
	"reflect"
	"testing"
)

func assertDeepEqual(t *testing.T, name string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s mismatch:\n  got:  %#v\n  want: %#v", name, got, want)
	}
}

type stubTransport struct {
	byOID     map[string]map[string]string
	walkByKey map[string]map[string]string
}

func walkKey(baseOID, community string) string {
	return baseOID + "|" + community
}

func (s stubTransport) Walk(_ *Client, baseOID string, community string) (map[string]string, error) {
	if s.walkByKey == nil {
		return map[string]string{}, nil
	}
	if out, ok := s.walkByKey[walkKey(baseOID, community)]; ok {
		return out, nil
	}
	return map[string]string{}, nil
}

func (s stubTransport) WalkWithOptions(c *Client, baseOID string, community string, _ *bool) (map[string]string, error) {
	return s.Walk(c, baseOID, community)
}

func (s stubTransport) WalkManyOIDs(_ *Client, oids []string, _ string, _ *bool) (map[string]map[string]string, error) {
	out := make(map[string]map[string]string, len(oids))
	for _, oid := range oids {
		out[oid] = s.byOID[oid]
	}
	return out, nil
}

func newClientWithStubbedTransport(
	t *testing.T,
	byOID map[string]map[string]string,
) *Client {
	t.Helper()
	return &Client{
		transport: stubTransport{
			byOID: byOID,
		},
	}
}

func newClientWithStubbedTransportAndWalk(
	t *testing.T,
	byOID map[string]map[string]string,
	walkByKey map[string]map[string]string,
) *Client {
	t.Helper()
	return &Client{
		Community: "public",
		transport: stubTransport{
			byOID:     byOID,
			walkByKey: walkByKey,
		},
	}
}

func TestCiscoIfaceL3CollectInterfacesWithStubbedSNMP(t *testing.T) {
	client := newClientWithStubbedTransport(t, map[string]map[string]string{
		ciscoL3InterfaceOIDs["ifName"]: {
			"10": "Vlanif10",
			"11": "Vlanif11",
		},
		ciscoL3InterfaceOIDs["ifAlias"]: {
			"10": "Uplink",
			"11": "Downlink",
		},
		ciscoL3InterfaceOIDs["routedV"]: {
			"100.10": "1",
			"200.10": "1",
			"300.11": "1",
			"bad":    "1",
		},
	})

	got, err := (&ciscoIfaceL3{}).CollectInterfaces(client)
	if err != nil {
		t.Fatalf("CollectInterfaces() returned error: %v", err)
	}

	p10 := got["Vlanif10"].(map[string]any)
	assertDeepEqual(t, "Vlanif10 metadata", map[string]any{
		"tag":     p10["tag"],
		"ifindex": p10["ifindex"],
		"descr":   p10["descr"],
	}, map[string]any{"tag": 1, "ifindex": 10, "descr": "Uplink"})
	assertDeepEqual(t, "Vlanif10 vlan map", p10["vlan"], map[int]int{100: 1, 200: 1})
}

func TestQBridgeGenericCollectorCollectInterfacesWithStubbedSNMP(t *testing.T) {
	client := newClientWithStubbedTransport(t, map[string]map[string]string{
		ifaceQBridgeCurrentOIDs["dot1qVlanCurrentEgressPorts"]: {
			"100": "\xc0", // first 2 ports egress
		},
		ifaceQBridgeCurrentOIDs["dot1qVlanCurrentUntaggedPorts"]: {
			"100": "\x80", // only first port untagged
		},
		ifaceQBridgeCurrentOIDs["dot1qPvid"]: {},
		qBridgeBaseIfOIDs["ifType"]: {
			"1": "6",
			"2": "161",
			"3": "24", // filtered out
		},
		qBridgeBaseIfOIDs["ifAdminStatus"]: {
			"1": "1",
			"2": "2",
			"3": "1",
		},
		qBridgeBaseIfOIDs["ifAlias"]: {
			"1": "Port1",
			"2": "Port2",
			"3": "Loopback",
		},
		qBridgeBaseIfOIDs["ifName"]: {
			"1": "Gi0/1",
			"2": "Po10",
			"3": "Lo0",
		},
	})

	c := &qBridgeGenericCollector{
		opts: qBridgeDefaultCurrentOptions(nil, QBridgeIfTypesL2StackLike()),
	}
	got, err := c.CollectInterfaces(client)
	if err != nil {
		t.Fatalf("CollectInterfaces() returned error: %v", err)
	}

	if _, ok := got["3"]; ok {
		t.Fatalf("ifType filter failed, got port 3 in output")
	}
	p1 := got["1"].(map[string]any)
	p2 := got["2"].(map[string]any)

	assertDeepEqual(t, "port1 metadata", map[string]any{
		"name":    p1["name"],
		"ifindex": p1["ifindex"],
		"descr":   p1["descr"],
	}, map[string]any{"name": "Gi0/1", "ifindex": 1, "descr": "Port1"})
	assertDeepEqual(t, "port2 flags", map[string]any{
		"disab": p2["disab"],
		"tag":   p2["tag"],
	}, map[string]any{"disab": 1, "tag": 1})
	assertDeepEqual(t, "port1 vlan", p1["vlan"], map[int]int{100: 1})
	assertDeepEqual(t, "port2 vlan", p2["vlan"], map[int]int{100: 1})
}

func TestHuaweiIfaceHWL2CollectInterfacesWithStubbedSNMP(t *testing.T) {
	client := newClientWithStubbedTransport(t, map[string]map[string]string{
		huaweiInterfaceOIDs["ifType"]: {
			"10": "6",
		},
		huaweiInterfaceOIDs["ifName"]: {
			"10": "Eth-Trunk10",
		},
		huaweiInterfaceOIDs["ifAlias"]: {
			"10": "Uplink",
		},
		huaweiInterfaceOIDs["ifAdminStatus"]: {
			"10": "1",
		},
		huaweiInterfaceOIDs["hwL2IfPortIfIndex"]: {
			"0": "10",
		},
		huaweiInterfaceOIDs["hwL2IfPortType"]: {
			"0": "1",
		},
		huaweiInterfaceOIDs["hwL2VlanPortList"]: {
			"hw.200": "\x80",
			"hw.1":   "\x80", // should be skipped by vid==1 guard
		},
		huaweiInterfaceOIDs["dot1qPvid"]: {
			"1": "200",
		},
	})

	got, err := (&huaweiIfaceHWL2{}).CollectInterfaces(client)
	if err != nil {
		t.Fatalf("CollectInterfaces() returned error: %v", err)
	}

	p := got["10"].(map[string]any)
	assertDeepEqual(t, "huawei metadata", map[string]any{
		"tag":     p["tag"],
		"name":    p["name"],
		"ifindex": p["ifindex"],
	}, map[string]any{"tag": 1, "name": "Eth-Trunk10", "ifindex": 10})
	assertDeepEqual(t, "huawei vlan map", p["vlan"], map[int]int{200: 1})
}

func TestQBridgeMACCollectMACWithStubbedSNMP(t *testing.T) {
	key := "100.1.2.3.4.5.6"
	client := newClientWithStubbedTransport(t, map[string]map[string]string{
		qbridgeFdbOIDs["dot1qTpFdbPort"]: {
			key: "7",
		},
		qbridgeFdbOIDs["dot1qTpFdbStatus"]: {
			key: "3",
		},
		qbridgeFdbOIDs["dot1dBasePortIfIdx"]: {
			"7": "70",
		},
	})

	got, err := (&qbridgeMAC{fdbWalkUsesGetBulk: true}).CollectMAC(
		client,
		&MacDbContext{IfIndexToPortID: map[int]int{70: 700}},
	)
	if err != nil {
		t.Fatalf("CollectMAC() returned error: %v", err)
	}

	if got["format"] != MacTableFormatFDB {
		t.Fatalf("unexpected format: %v", got["format"])
	}
	entries, ok := got["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("unexpected entries: %v", got["entries"])
	}
	row := entries[0].(map[string]any)
	assertDeepEqual(t, "qbridge mac row", row, map[string]any{
		"ifindex": 70,
		"vlan":    100,
		"mac":     "01:02:03:04:05:06",
		"status":  3,
		"port_id": 700,
	})
}
