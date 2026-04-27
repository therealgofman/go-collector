package snmp

import "fmt"

var ciscoPortSecurityOIDs = map[string]string{
	"psecStatus":   "1.3.6.1.4.1.9.9.315.1.2.1.1.1",
	"psecMacLimit": "1.3.6.1.4.1.9.9.315.1.2.1.1.3",
}

type ciscoPortSecurityEnricher struct{}

// NewCiscoPortSecurityEnricher обогащает порты Cisco полями psec_status и psec_mac_limit.
func NewCiscoPortSecurityEnricher() VendorIfaceEnricher {
	return &ciscoPortSecurityEnricher{}
}

func (*ciscoPortSecurityEnricher) EnrichInterfaces(c *Client, ports InterfacePorts) error {
	w, err := walkMany(c, ciscoPortSecurityOIDs, "")
	if err != nil {
		return err
	}
	for key, p := range ports {
		if p.IfIndex <= 0 {
			continue
		}
		ifidx := fmt.Sprintf("%d", p.IfIndex)
		params := map[string]string{}
		if v, ok := w["psecStatus"][ifidx]; ok {
			params["psec_status"] = v
		}
		if v, ok := w["psecMacLimit"][ifidx]; ok {
			params["psec_mac_limit"] = v
		}
		if len(params) > 0 {
			p.Persist = append(p.Persist, PortPersistOp{Query: "upsert_port_security", Params: params})
		}
		ports[key] = p
	}
	return nil
}
