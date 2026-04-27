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
