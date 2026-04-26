package snmp

import "strconv"
import "go-collector/internal/helpers"

var ciscoPortSecurityOIDs = map[string]string{
	"psecStatus":   "1.3.6.1.4.1.9.9.315.1.2.1.1.1",
	"psecMacLimit": "1.3.6.1.4.1.9.9.315.1.2.1.1.3",
}

type ciscoPortSecurityEnricher struct{}

// NewCiscoPortSecurityEnricher обогащает порты Cisco полями psec_status и psec_mac_limit.
func NewCiscoPortSecurityEnricher() VendorIfaceEnricher {
	return &ciscoPortSecurityEnricher{}
}

func (*ciscoPortSecurityEnricher) EnrichInterfaces(c *Client, ports map[string]any) error {
	w, err := walkMany(c, ciscoPortSecurityOIDs, "")
	if err != nil {
		return err
	}
	for _, raw := range ports {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		ifindex, ok := helpers.AsInt(p["ifindex"])
		if !ok || ifindex <= 0 {
			continue
		}
		ifidx := strconv.Itoa(ifindex)
		if v, ok := w["psecStatus"][ifidx]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				p["psec_status"] = n
			}
		}
		if v, ok := w["psecMacLimit"][ifidx]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				p["psec_mac_limit"] = n
			}
		}
		params := map[string]any{}
		if v, ok := p["psec_status"]; ok {
			params["psec_status"] = v
		}
		if v, ok := p["psec_mac_limit"]; ok {
			params["psec_mac_limit"] = v
		}
		if len(params) > 0 {
			AddPortPersistOp(p, "upsert_port_security", params)
		}
	}
	return nil
}
