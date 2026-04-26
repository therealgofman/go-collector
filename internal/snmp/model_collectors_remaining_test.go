package snmp

import (
	"reflect"
	"testing"
)

func TestCiscoIfaceL2CollectInterfaces(t *testing.T) {
	client := newClientWithStubbedTransportAndWalk(t, map[string]map[string]string{
		ciscoL2InterfaceOIDs["ifAdminStatus"]: {"10": "1", "20": "2"},
		ciscoL2InterfaceOIDs["ifName"]:        {"10": "GigabitEthernet0/1", "20": "GigabitEthernet0/2"},
		ciscoL2InterfaceOIDs["ifAlias"]:       {"10": "p1", "20": "p2"},
		ciscoL2InterfaceOIDs["ifType"]:        {"10": "6", "20": "6"},
		ciscoL2InterfaceOIDs["ifXconnectPorts"]: {},
		ciscoL2InterfaceOIDs["untaggedPorts"]:   {"100": "\x80"},
		ciscoL2InterfaceOIDs["encapsulation"]:   {"20": "4"},
		ciscoL2InterfaceOIDs["tag1"]:            {"20": ""},
		ciscoL2InterfaceOIDs["tag2"]:            {},
		ciscoL2InterfaceOIDs["tag3"]:            {},
		ciscoL2InterfaceOIDs["tag4"]:            {},
	}, map[string]map[string]string{
		walkKey("1.3.6.1.2.1.17.1.4.1.2", "public@100"): {"1": "10", "2": "20"},
	})
	got, err := (&ciscoIfaceL2{}).CollectInterfaces(client)
	if err != nil {
		t.Fatalf("CollectInterfaces error: %v", err)
	}
	p := got["10"].(map[string]any)
	assertDeepEqual(t, "cisco l2 port10 vlan", p["vlan"], map[int]int{100: 1})
}

func TestSNRIfaceCollectInterfaces(t *testing.T) {
	client := newClientWithStubbedTransport(t, map[string]map[string]string{
		"1.3.6.1.4.1.40418.7.100.3.2.1.2":  {"1": "Port1"},
		"1.3.6.1.2.1.31.1.1.1.18":          {"1": "desc"},
		"1.3.6.1.4.1.40418.7.100.5.1.1.2":  {"100": "1", "200": "1"},
		"1.3.6.1.4.1.40418.7.100.3.2.1.15": {"1": "2"},
		"1.3.6.1.4.1.40418.7.100.3.2.1.16": {"1": "100"},
		"1.3.6.1.4.1.40418.7.100.3.2.1.20": {"1": "200;"},
		"1.3.6.1.4.1.40418.7.100.5.3.1.4":  {"300.1": "x"},
	})
	got, err := (&snrIface{}).CollectInterfaces(client)
	if err != nil {
		t.Fatalf("CollectInterfaces error: %v", err)
	}
	p := got["1"].(map[string]any)
	assertDeepEqual(t, "snr vlan", p["vlan"], map[int]int{100: 1, 200: 1, 300: 1})
	assertDeepEqual(t, "snr tag", p["tag"], 1)
}

func TestHPEIfaceQBridgeStaticCollectInterfaces(t *testing.T) {
	client := newClientWithStubbedTransport(t, map[string]map[string]string{
		hpeQBridgeInterfaceOIDs["dot1qVlanStaticEgressPorts"]:   {"100": "\x80"},
		hpeQBridgeInterfaceOIDs["dot1qVlanStaticUntaggedPorts"]: {"100": "\x00"},
		hpeQBridgeInterfaceOIDs["dot1qPvid"]:                    {},
		hpeQBridgeInterfaceOIDs["dot1dBasePortIfIndex"]:         {"1": "10"},
		hpeQBridgeInterfaceOIDs["ifAdminStatus"]:                {"10": "1"},
		hpeQBridgeInterfaceOIDs["ifOperStatus"]:                 {"10": "1"},
		hpeQBridgeInterfaceOIDs["ifHighSpeed"]:                  {"10": "10000"},
		hpeQBridgeInterfaceOIDs["ifAlias"]:                      {"10": "uplink"},
		hpeQBridgeInterfaceOIDs["ifName"]:                       {"10": "Ten-GigabitEthernet1/0/1"},
		hpeQBridgeInterfaceOIDs["ifType"]:                       {"10": "6"},
	})
	got, err := (&hpeIfaceQBridgeStatic{}).CollectInterfaces(client)
	if err != nil {
		t.Fatalf("CollectInterfaces error: %v", err)
	}
	p := got["10"].(map[string]any)
	assertDeepEqual(t, "hpe vlan", p["vlan"], map[int]int{100: 1})
	assertDeepEqual(t, "hpe tag", p["tag"], 1)
}

func TestExtremeIfaceCollectInterfaces(t *testing.T) {
	client := newClientWithStubbedTransport(t, map[string]map[string]string{
		"1.3.6.1.2.1.2.2.1.7":          {"10": "1"},
		"1.3.6.1.2.1.31.1.1.1.18":      {"10": "ext"},
		"1.3.6.1.2.1.2.2.1.3":          {"10": "6"},
		"1.3.6.1.2.1.31.1.1.1.1":       {"10": "xe-1"},
		"1.3.6.1.4.1.1916.1.2.1.2.1.10": {"1": "200"},
		"1.3.6.1.4.1.1916.1.2.6.1.1.1": {"1.1": "\x80"},
		"1.3.6.1.4.1.1916.1.2.6.1.1.2": {"1.1": "\x00"},
		"1.3.6.1.2.1.17.1.4.1.2":       {"1": "10"},
	})
	got, err := (&extremeIface{typ: 3}).CollectInterfaces(client)
	if err != nil {
		t.Fatalf("CollectInterfaces error: %v", err)
	}
	p := got["xe-1"].(map[string]any)
	assertDeepEqual(t, "extreme vlan", p["vlan"], map[int]int{200: 1})
	assertDeepEqual(t, "extreme tag", p["tag"], 1)
}

func TestDLinkCollectorsCollectInterfaces(t *testing.T) {
	t.Run("1210", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			"1.3.6.1.2.1.2.2.1.3":          {"1": "6"},
			"1.3.6.1.4.1.171.10.75.5.1.14.1.3": {"1.100": "Port1"},
			"1.3.6.1.4.1.171.10.75.5.7.6.1.5":  {"100": "1"},
			"1.3.6.1.4.1.171.10.75.5.7.6.1.2":  {"100": "\x80"},
			"1.3.6.1.4.1.171.10.75.5.7.6.1.4":  {"100": "\x80"},
			"1.3.6.1.4.1.171.10.75.5.27.2.1.4": {},
		})
		got, err := (&dlinkIface1210{}).CollectInterfaces(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		assertDeepEqual(t, "dlink1210 vlan", got["1"].(map[string]any)["vlan"], map[int]int{100: 1})
	})

	t.Run("3100", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			ifaceQBridgeCurrentOIDs["dot1qVlanCurrentEgressPorts"]:   {"100": "\x80"},
			ifaceQBridgeCurrentOIDs["dot1qVlanCurrentUntaggedPorts"]: {"100": "\x00"},
			ifaceQBridgeCurrentOIDs["dot1qPvid"]:                     {},
			"1.3.6.1.2.1.31.1.1.1.18":                                {"1": "p1"},
			"1.3.6.1.2.1.2.2.1.8":                                    {"1": "1"},
			"1.3.6.1.2.1.2.2.1.3":                                    {"1": "6"},
			"1.3.6.1.2.1.2.2.1.7":                                    {"1": "2"},
		})
		got, err := (&dlinkIface3100{}).CollectInterfaces(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		p := got["1"].(map[string]any)
		assertDeepEqual(t, "dlink3100 vlan", p["vlan"], map[int]int{100: 1})
		assertDeepEqual(t, "dlink3100 disab", p["disab"], 1)
	})

	t.Run("3028", func(t *testing.T) {
		client := newClientWithStubbedTransportAndWalk(t, map[string]map[string]string{
			ifaceQBridgeStaticOIDs["dot1qVlanStaticEgressPorts"]:   {"100": "\x80"},
			ifaceQBridgeStaticOIDs["dot1qVlanStaticUntaggedPorts"]: {"100": "\x80"},
			ifaceQBridgeStaticOIDs["dot1qPvid"]:                    {},
			qBridgeBaseIfOIDs["ifAdminStatus"]:                     {"1": "1"},
			qBridgeBaseIfOIDs["ifAlias"]:                           {"1": "p1"},
			qBridgeBaseIfOIDs["ifType"]:                            {"1": "6"},
			qBridgeBaseIfOIDs["ifName"]:                            {"1": "if1"},
			"1.3.6.1.2.1.1.1":                                      {"0": "DES-3028"},
		}, map[string]map[string]string{
			walkKey("1.3.6.1.4.1.171.11.116.2.2.7.8.1.3", ""): {},
			walkKey("1.3.6.1.4.1.171.11.116.2.2.7.8.1.4", ""): {},
		})
		got, err := (&dlinkIface3028{}).CollectInterfaces(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		assertDeepEqual(t, "dlink3028 vlan", got["1"].(map[string]any)["vlan"], map[int]int{100: 1})
	})

	t.Run("2108", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			"1.3.6.1.4.1.171.10.61.2.11.6.1.1": {"1": "1"},
			"1.3.6.1.2.1.2.2.1.7":              {"1": "1"},
			"1.3.6.1.4.1.171.10.61.2.13.1.1.3": {"100": "\x80"},
			"1.3.6.1.4.1.171.10.61.2.13.1.1.4": {"100": "\x80"},
		})
		got, err := (&dlinkIface2108{}).CollectInterfaces(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		assertDeepEqual(t, "dlink2108 vlan", got["1"].(map[string]any)["vlan"], map[int]int{100: 1})
	})

	t.Run("1100", func(t *testing.T) {
		client := newClientWithStubbedTransportAndWalk(t, map[string]map[string]string{
			"1.3.6.1.2.1.31.1.1.1.18": {"1": "p1"},
			"1.3.6.1.2.1.2.2.1.8":     {"1": "1"},
			"1.3.6.1.2.1.2.2.1.3":     {"1": "6"},
			"1.3.6.1.2.1.2.2.1.7":     {"1": "1"},
		}, map[string]map[string]string{
			walkKey("1.3.6.1.4.1.171.10.134.1.1.7.6.1.4", ""): {"100": "\x80"},
			walkKey("1.3.6.1.4.1.171.10.134.1.1.7.6.1.2", ""): {"100": "\x80"},
			walkKey("1.3.6.1.4.1.171.10.134.1.1.7.7.1.1", ""): {},
		})
		got, err := (&dlinkIface1100{}).CollectInterfaces(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		assertDeepEqual(t, "dlink1100 vlan", got["1"].(map[string]any)["vlan"], map[int]int{100: 1})
	})
}

func TestHuaweiQBridgeAndJuniperIfaceCollectors(t *testing.T) {
	t.Run("huaweiQBridge", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			ifaceQBridgeCurrentOIDs["dot1qVlanCurrentEgressPorts"]:   {"100": "\x80"},
			ifaceQBridgeCurrentOIDs["dot1qVlanCurrentUntaggedPorts"]: {"100": "\x00"},
			ifaceQBridgeCurrentOIDs["dot1qPvid"]:                     {},
			qBridgeBaseIfOIDs["ifAdminStatus"]:                       {"10": "1"},
			qBridgeBaseIfOIDs["ifAlias"]:                             {"10": "h1"},
			qBridgeBaseIfOIDs["ifType"]:                              {"10": "6"},
			qBridgeBaseIfOIDs["ifName"]:                              {"10": "Eth1"},
			"1.3.6.1.4.1.2011.5.25.42.1.1.1.3.1.2":                   {"0": "10"},
		})
		got, err := (&huaweiIfaceQBridge{}).CollectInterfaces(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		assertDeepEqual(t, "huawei qbridge vlan", got["10"].(map[string]any)["vlan"], map[int]int{})
	})

	t.Run("juniperIfaceQBridgeStatic", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			juniperQBridgeStaticInterfaceOIDs["ifAdminStatus"]:              {"1": "1", "2": "1"},
			juniperQBridgeStaticInterfaceOIDs["ifType"]:                     {"1": "6", "2": "6"},
			juniperQBridgeStaticInterfaceOIDs["ifName"]:                     {"1": "ge-0/0/1", "2": "ge-0/0/1.100"},
			juniperQBridgeStaticInterfaceOIDs["ifAlias"]:                    {"1": "base", "2": "sub"},
			juniperQBridgeStaticInterfaceOIDs["dot1qVlanStaticEgressPorts"]: {"100": "1"},
			juniperQBridgeStaticInterfaceOIDs["dot1dBasePortIfIndex"]:       {"1": "1"},
		})
		got, err := (&juniperIfaceQBridgeStatic{}).CollectInterfaces(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		p := got["1"].(map[string]any)
		assertDeepEqual(t, "juniper iface vlan", p["vlan"], map[int]int{100: 1})
		assertDeepEqual(t, "juniper iface tag", p["tag"], 1)
	})
}

func TestCollectorsARPImplementations(t *testing.T) {
	t.Run("qbridgeMainARP", func(t *testing.T) {
		client := newClientWithStubbedTransportAndWalk(t, nil, map[string]map[string]string{
			walkKey("1.3.6.1.2.1.31.1.1.1.1", ""):    {"10": "Vlan100"},
			walkKey("1.3.6.1.2.1.17.7.1.4.3.1.1", ""): {"100": "Vlan100"},
			walkKey("1.3.6.1.2.1.4.22.1.2", ""):      {"10.192.0.2.1": "aa:bb:cc:dd:ee:ff"},
		})
		got, err := (&qbridgeMainARP{}).CollectARP(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got["100"]["192.0.2.1"] != "aa:bb:cc:dd:ee:ff" {
			t.Fatalf("unexpected result: %v", got)
		}
	})

	t.Run("juniperARP", func(t *testing.T) {
		client := newClientWithStubbedTransportAndWalk(t, nil, map[string]map[string]string{
			walkKey(juniperARPOIDs["ifName"], ""): {"10": "irb.100"},
			walkKey(juniperARPOIDs["vsn"], ""):    {},
			walkKey(juniperARPOIDs["arp"], ""):    {"10.192.0.2.2": "aa:aa:aa:aa:aa:aa"},
		})
		got, err := (&juniperARP{}).CollectARP(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got["100"]["192.0.2.2"] != "aa:aa:aa:aa:aa:aa" {
			t.Fatalf("unexpected result: %v", got)
		}
	})

	t.Run("extremeARP", func(t *testing.T) {
		client := newClientWithStubbedTransportAndWalk(t, nil, map[string]map[string]string{
			walkKey("1.3.6.1.4.1.1916.1.2.1.2.1.10", ""): {"100.10": "10"},
			walkKey("1.3.6.1.2.1.4.22.1.2", ""):         {"10.192.0.2.3": "bb:bb:bb:bb:bb:bb"},
		})
		got, err := (&extremeARP{}).CollectARP(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got["100"]["192.0.2.3"] != "bb:bb:bb:bb:bb:bb" {
			t.Fatalf("unexpected result: %v", got)
		}
	})

	t.Run("extremeXSeriesARP", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			"1.3.6.1.4.1.1916.1.2.1.2.1.10": {"100": "200"},
			"1.3.6.1.4.1.1916.1.16.2.1.2":   {"r1": "192.0.2.4"},
			"1.3.6.1.4.1.1916.1.16.2.1.3":   {"r1": "\x01\x02\x03\x04\x05\x06"},
			"1.3.6.1.4.1.1916.1.16.2.1.4":   {"r1": "100"},
		})
		got, err := (&extremeXSeriesARP{}).CollectARP(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got["200"]["192.0.2.4"] != "01:02:03:04:05:06" {
			t.Fatalf("unexpected result: %v", got)
		}
	})

	t.Run("ciscoARPVlanIf", func(t *testing.T) {
		client := newClientWithStubbedTransportAndWalk(t, nil, map[string]map[string]string{
			walkKey("1.3.6.1.2.1.2.2.1.2", ""): {"10": "Vlan100"},
			walkKey("1.3.6.1.2.1.4.22.1.2", ""): {"10.192.0.2.5": "cc:cc:cc:cc:cc:cc"},
		})
		got, err := (&ciscoARPVlanIf{}).CollectARP(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got["100"]["192.0.2.5"] != "cc:cc:cc:cc:cc:cc" {
			t.Fatalf("unexpected result: %v", got)
		}
	})

	t.Run("ciscoARPL3Router", func(t *testing.T) {
		client := newClientWithStubbedTransportAndWalk(t, nil, map[string]map[string]string{
			walkKey("1.3.6.1.4.1.9.9.128.1.1.1.1.3", ""): {"100.10": "1"},
			walkKey("1.3.6.1.2.1.4.22.1.2", ""):         {"10.192.0.2.6": "dd:dd:dd:dd:dd:dd"},
			walkKey("1.3.6.1.3.118.1.2.1.1.6", ""):      {"114.101.100.10": "1"},
		})
		got, err := (&ciscoARPL3Router{}).CollectARP(client)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got["100@red"]["192.0.2.6"] != "dd:dd:dd:dd:dd:dd" {
			t.Fatalf("unexpected result: %v", got)
		}
	})
}

func TestCollectorsMACImplementations(t *testing.T) {
	t.Run("juniperQBridgeMAC", func(t *testing.T) {
		key := "1.1.2.3.4.5.6"
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			juniperQBridgeFdbOIDs["dot1qTpFdbPort"]:     {key: "7"},
			juniperQBridgeFdbOIDs["dot1qTpFdbStatus"]:   {key: "3"},
			juniperQBridgeFdbOIDs["dot1dBasePortIfIdx"]: {"7": "70"},
			juniperQBridgeFdbOIDs["jnxL2aldVlanTag"]:    {"idx1": "200"},
			juniperQBridgeFdbOIDs["jnxL2aldVlanFdbId"]:  {"idx1": "1"},
		})
		got, err := (&juniperQBridgeMAC{}).CollectMAC(client, &MacDbContext{IfIndexToPortID: map[int]int{70: 700}})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		row := got["entries"].([]any)[0].(map[string]any)
		if row["vlan"] != 200 || row["ifindex"] != 70 {
			t.Fatalf("unexpected row: %v", row)
		}
	})

	t.Run("extremePrivateMAC", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			extremePrivateFdbOIDs["addr"]:    {"1.1": "\x01\x02\x03\x04\x05\x06"},
			extremePrivateFdbOIDs["ifi"]:     {"1.1": "10"},
			extremePrivateFdbOIDs["sta"]:     {"1.1": "3"},
			extremePrivateFdbOIDs["vlans"]:   {"100": "200"},
			extremePrivateFdbOIDs["vmapraw"]: {"1.1": "100"},
		})
		got, err := (&extremePrivateMAC{}).CollectMAC(client, &MacDbContext{IfIndexToPortID: map[int]int{10: 110}})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		row := got["entries"].([]any)[0].(map[string]any)
		if row["vlan"] != 200 || row["ifindex"] != 10 || row["port_id"] != 110 {
			t.Fatalf("unexpected row: %v", row)
		}
	})

	t.Run("extremeXSeriesMAC", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			extremeXSeriesFdbOIDs["vid"]:    {"100": "200"},
			extremeXSeriesFdbOIDs["port"]:   {"1.2.3.4.5.6.100": "10"},
			extremeXSeriesFdbOIDs["status"]: {"1.2.3.4.5.6.100": "3"},
		})
		got, err := (&extremeXSeriesMAC{}).CollectMAC(client, &MacDbContext{IfIndexToPortID: map[int]int{10: 210}})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		row := got["entries"].([]any)[0].(map[string]any)
		if row["vlan"] != 200 || row["ifindex"] != 10 || row["port_id"] != 210 {
			t.Fatalf("unexpected row: %v", row)
		}
	})

	t.Run("bridgeMIBMAC", func(t *testing.T) {
		client := newClientWithStubbedTransport(t, map[string]map[string]string{
			fdbOIDs["dot1dTpFdbPort"]:       {"1.2.3.4.5.6": "7"},
			fdbOIDs["dot1dTpFdbStatus"]:     {"1.2.3.4.5.6": "3"},
			fdbOIDs["dot1dBasePortIfIndex"]: {"7": "70"},
		})
		got, err := (&bridgeMIBMAC{}).CollectMAC(client, &MacDbContext{
			IfIndexToPortID:       map[int]int{70: 700},
			IfIndexToUntaggedVLAN: map[int]int{70: 300},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		row := got["entries"].([]any)[0].(map[string]any)
		if row["vlan"] != 300 || row["ifindex"] != 70 || row["port_id"] != 700 {
			t.Fatalf("unexpected row: %v", row)
		}
	})
}

func TestCiscoPortSecurityEnricher(t *testing.T) {
	client := newClientWithStubbedTransport(t, map[string]map[string]string{
		ciscoPortSecurityOIDs["psecStatus"]:   {"10": "1"},
		ciscoPortSecurityOIDs["psecMacLimit"]: {"10": "32"},
	})
	ports := map[string]any{
		"10": map[string]any{"ifindex": 10},
	}
	if err := (&ciscoPortSecurityEnricher{}).EnrichInterfaces(client, ports); err != nil {
		t.Fatalf("EnrichInterfaces error: %v", err)
	}
	p := ports["10"].(map[string]any)
	if p["psec_status"] != 1 || p["psec_mac_limit"] != 32 {
		t.Fatalf("unexpected enriched data: %v", p)
	}
	persist, ok := p["persist"].([]any)
	if !ok || len(persist) == 0 {
		t.Fatalf("expected persist op, got %v", p["persist"])
	}
}

func TestBridgeMIBMACIdxCommunityNoVLANs(t *testing.T) {
	client := newClientWithStubbedTransport(t, map[string]map[string]string{})
	got, err := (&bridgeMIBMAC{fdbIdxCommunity: true}).CollectMAC(client, &MacDbContext{})
	if err != nil {
		t.Fatalf("CollectMAC error: %v", err)
	}
	meta := got["meta"].(map[string]any)
	if meta["obsolete_by_vlan"] != true {
		t.Fatalf("expected obsolete_by_vlan=true, got %v", meta)
	}
	if _, ok := meta["warning"]; !ok {
		t.Fatalf("expected warning in meta, got %v", meta)
	}
}

func TestQBridgeIfTypesFactoryReturnsCopy(t *testing.T) {
	a := QBridgeIfTypesL2StackLike()
	b := QBridgeIfTypesL2StackLike()
	delete(a, "6")
	if !reflect.DeepEqual(b, map[string]struct{}{"6": {}, "62": {}, "117": {}, "161": {}}) {
		t.Fatalf("expected independent copy, got %v", b)
	}
}
