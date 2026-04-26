package snmp

// noopARPCollector — VendorARPCollector без SNMP-запросов.
// Используется, когда для модели нужно явно отключить сбор ARP.
type noopARPCollector struct{}

// NewNoopARP возвращает no-op стратегию сбора ARP.
func NewNoopARP() VendorARPCollector {
	return &noopARPCollector{}
}

// CollectARP всегда возвращает пустой результат без ошибок.
func (*noopARPCollector) CollectARP(*Client) (map[string]map[string]string, error) {
	return map[string]map[string]string{}, nil
}
