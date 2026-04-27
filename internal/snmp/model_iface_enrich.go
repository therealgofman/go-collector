package snmp

import "fmt"

type ifaceCollectorWithEnrich struct {
	base      VendorIfaceCollector
	enrichers []VendorIfaceEnricher
}

// NewIfaceCollectorWithEnrich оборачивает базовый collector цепочкой enrichers.
func NewIfaceCollectorWithEnrich(base VendorIfaceCollector, enrichers ...VendorIfaceEnricher) VendorIfaceCollector {
	if base == nil {
		return nil
	}
	if len(enrichers) == 0 {
		return base
	}
	return &ifaceCollectorWithEnrich{base: base, enrichers: enrichers}
}

func (w *ifaceCollectorWithEnrich) CollectInterfaces(c *Client) (InterfacePorts, error) {
	ports, err := w.base.CollectInterfaces(c)
	if err != nil {
		return nil, err
	}
	for _, enr := range w.enrichers {
		if enr == nil {
			continue
		}
		if err := enr.EnrichInterfaces(c, ports); err != nil {
			return nil, fmt.Errorf("iface enrich failed: %w", err)
		}
	}
	return ports, nil
}
