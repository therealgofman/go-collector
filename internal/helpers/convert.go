package helpers

import (
	"fmt"
	"strconv"
	"strings"
)

// AsString приводит значения к строке (в т.ч. []byte из MySQL).
func AsString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(x)
	default:
		return fmt.Sprint(v)
	}
}

// AsInt приводит числовые/строковые значения к int.
func AsInt(v any) (int, bool) {
	if v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case int:
		return x, true
	case int8:
		return int(x), true
	case int16:
		return int(x), true
	case int32:
		return int(x), true
	case int64:
		return int(x), true
	case uint:
		return int(x), true
	case uint8:
		return int(x), true
	case uint16:
		return int(x), true
	case uint32:
		return int(x), true
	case uint64:
		return int(x), true
	case float32:
		return int(x), true
	case float64:
		return int(x), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	case []byte:
		n, err := strconv.Atoi(strings.TrimSpace(string(x)))
		return n, err == nil
	default:
		n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(v)))
		return n, err == nil
	}
}

// PortsToAnyMap конвертирует map портов к общему возвращаемому типу.
func PortsToAnyMap(ports map[string]map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range ports {
		out[k] = v
	}
	return out
}

// FirstExistingInt возвращает первое успешно преобразованное число по ключам в порядке приоритета.
func FirstExistingInt(m map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if n, ok := AsInt(v); ok {
				return n, true
			}
		}
	}
	return 0, false
}

// ToIntMap конвертирует map с числовыми значениями к map[string]int.
func ToIntMap(v any) map[string]int {
	out := map[string]int{}
	switch m := v.(type) {
	case map[string]any:
		for k, raw := range m {
			if n, ok := AsInt(raw); ok {
				out[k] = n
			}
		}
	case map[string]int:
		for k, n := range m {
			out[k] = n
		}
	}
	return out
}

// ToNestedIntMap конвертирует вложенную map к map[string]map[string]int.
func ToNestedIntMap(v any) map[string]map[string]int {
	out := map[string]map[string]int{}
	switch root := v.(type) {
	case map[string]any:
		for k, raw := range root {
			out[k] = ToIntMap(raw)
		}
	case map[string]map[string]any:
		for k, raw := range root {
			out[k] = ToIntMap(raw)
		}
	case map[string]map[string]int:
		for k, raw := range root {
			out[k] = ToIntMap(raw)
		}
	}
	return out
}
