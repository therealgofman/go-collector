package snmp

// AddPortPersistOp добавляет persist-операцию в порт в универсальном формате:
// p["persist"] = []any{ {query: "...", params: {...}}, ... }.
// Если в порту используется map-форма persist, операция записывается как m[query]=params.
func AddPortPersistOp(port map[string]any, query string, params map[string]any) {
	if port == nil || query == "" {
		return
	}
	if params == nil {
		params = map[string]any{}
	}

	if raw, ok := port["persist"]; ok && raw != nil {
		if m, ok := raw.(map[string]any); ok {
			m[query] = params
			port["persist"] = m
			return
		}
		if arr, ok := raw.([]any); ok {
			for i, it := range arr {
				item, ok := it.(map[string]any)
				if !ok {
					continue
				}
				if item["query"] == query {
					item["params"] = params
					arr[i] = item
					port["persist"] = arr
					return
				}
			}
			arr = append(arr, map[string]any{
				"query":  query,
				"params": params,
			})
			port["persist"] = arr
			return
		}
	}

	port["persist"] = []any{
		map[string]any{
			"query":  query,
			"params": params,
		},
	}
}
