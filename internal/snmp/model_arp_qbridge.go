package snmp

// qbridgeMainARP — VendorARPCollector: базовый сбор Q-BRIDGE + ARP; hooks — расширение карты ifIndex→VLAN.
type qbridgeMainARP struct {
	hooks qBridgeARPHooks
}

// NewQBridgeMainARP возвращает общий ARP-сборщик Q-BRIDGE; hooks может быть nil.
func NewQBridgeMainARP(hooks qBridgeARPHooks) VendorARPCollector {
	return &qbridgeMainARP{hooks: hooks}
}

// NewHuaweiARPQBridge — совместимый алиас для Huawei-конфигураций на базе общего Q-BRIDGE-сборщика.
func NewHuaweiARPQBridge(hooks qBridgeARPHooks) VendorARPCollector {
	return NewQBridgeMainARP(hooks)
}

// CollectARP (Q-BRIDGE main): ifName extended, dot1qVlanStaticName, ARP; затем hook MergeIfIndexToVLANForARP при наличии.
func (m *qbridgeMainARP) CollectARP(c *Client) (map[string]map[string]string, error) {
	ifn, err := c.Walk("1.3.6.1.2.1.31.1.1.1.1", "")
	if err != nil {
		return nil, err
	}
	vsn, err := c.Walk("1.3.6.1.2.1.17.7.1.4.3.1.1", "")
	if err != nil {
		return nil, err
	}
	arp, err := c.Walk("1.3.6.1.2.1.4.22.1.2", "")
	if err != nil {
		return nil, err
	}
	ivQ := ifindexToVLANQBridge(ifn, vsn)
	iv := ivQ
	if m.hooks != nil {
		iv = m.hooks.MergeIfIndexToVLANForARP(ivQ, ifn, vsn)
	}
	return joinARPToVLAN(arp, iv), nil
}
