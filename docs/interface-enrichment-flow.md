# Поток обогащения интерфейсов (collector -> enricher -> persist)

Этот документ показывает, как добавлять и сохранять дополнительные данные по интерфейсам
(например, `port-security`) без изменения базовых таблиц портов.

Общий архитектурный контекст: `docs/architecture-overview.md`.

## 1) Базовый collector возвращает порты

Любой `VendorIfaceCollector` возвращает `map[string]any`, где каждое значение — объект порта.

Минимальная форма порта:

```go
ports["10101"] = map[string]any{
	"ifindex": 10101,
	"name":    "Ten-GigabitEthernet1/0/1",
	"descr":   "Uplink",
	"tag":     1,
	"disab":   0,
	"vlan":    map[int]int{10: 1, 20: 1},
}
```

## 2) Enricher добавляет предметные данные

Добавьте один или несколько `VendorIfaceEnricher` и объедините их в цепочку через:

`snmp.NewIfaceCollectorWithEnrich(base, enricher1, enricher2, ...)`.

Рекомендуемый подход: использовать helper `snmp.AddPortPersistOp(...)` внутри enricher,
чтобы для каждой новой фичи не пришлось менять слой persist.

Пример результата enricher для одного порта:

```go
p["persist"] = []any{
	map[string]any{
		"query": "upsert_port_security",
		"params": map[string]any{
			"enabled":      1,
			"max_mac":      32,
			"current_mac":  7,
			"violation":    "restrict",
			"last_updated": 1745686200,
		},
	},
}
```

Пример использования helper:

```go
snmp.AddPortPersistOp(p, "upsert_port_security", map[string]any{
	"enabled": 1,
	"max_mac": 32,
})
```

Альтернативная компактная форма (тоже поддерживается):

```go
p["persist"] = map[string]any{
	"upsert_port_security": map[string]any{
		"enabled": 1,
		"max_mac": 32,
	},
}
```

## 3) Factory подключает flow модели

Фабрика моделей решает, какая цепочка collector/enricher будет использована.

Пример (`internal/snmp/models/factory.go`):

```go
m.ifaceCollect = snmp.NewIfaceCollectorWithEnrich(
	snmp.NewCiscoIfaceL2(),
	snmp.NewCiscoPortSecurityEnricher(), // ваш enricher
)
```

## 4) Persist выполняет операции по порту

`PersistInterfaces` / `fillTablesFromInterfaces` делает:

1. Upsert базовых данных порта (`update_port` / `insert_port`)
2. Синхронизацию `port2vlan`
3. Выполнение дополнительных операций из `port["persist"]`

Дополнительно: все нестандартные поля порта (кроме базовых `ifindex/name/tag/descr/disab/vlan/persist`)
автоматически прокидываются в bind для `update_port` и `insert_port`.
Это позволяет компаниям сохранять расширенные колонки прямо в таблицу портов
только через правку SQL-шаблона в `company.yaml`, без изменений кода persist.

Для каждой операции persist автоматически добавляет базовые bind-параметры:

- `switch_id`
- `port_id`
- `ifindex`
- `name`
- `trunk`
- `description`
- `disabled`

После этого он объединяет их с пользовательскими `params` из collector/enricher.

## 5) SQL-query задается в YAML компании

Добавьте именованный query в `config/companies/<company>.yaml`:

```yaml
queries:
  upsert_port_security:
    template: |
      INSERT INTO d_port_security (
        port_id,
        enabled,
        max_mac,
        current_mac,
        violation,
        updated_at
      ) VALUES (
        :port_id,
        :enabled,
        :max_mac,
        :current_mac,
        :violation,
        FROM_UNIXTIME(:last_updated)
      )
      ON DUPLICATE KEY UPDATE
        enabled = VALUES(enabled),
        max_mac = VALUES(max_mac),
        current_mac = VALUES(current_mac),
        violation = VALUES(violation),
        updated_at = VALUES(updated_at)
```

При необходимости можно отключить эту операцию для конкретной компании:

```yaml
company:
  persist_disabled_queries:
    - upsert_port_security
```

## 6) Сквозной пример (один порт)

Входные данные от collector/enricher:

```go
ports["10101"] = map[string]any{
	"ifindex": 10101,
	"name":    "Ten-GigabitEthernet1/0/1",
	"vlan":    map[int]int{10: 1},
	"persist": []any{
		map[string]any{
			"query": "upsert_port_security",
			"params": map[string]any{
				"enabled":      1,
				"max_mac":      32,
				"current_mac":  7,
				"violation":    "restrict",
				"last_updated": 1745686200,
			},
		},
	},
}
```

Итоговый bind, который persist передаст в SQL:

```text
{
  switch_id: 123,
  port_id: 4567,
  ifindex: 10101,
  name: "Ten-GigabitEthernet1/0/1",
  trunk: 0,
  description: "",
  disabled: 0,
  enabled: 1,
  max_mac: 32,
  current_mac: 7,
  violation: "restrict",
  last_updated: 1745686200
}
```

## 7) Рекомендуемые соглашения

- Имена query (Рекомендуемое имя): `upsert_port_<feature>`
- Выход collector должен быть transport-like; бизнес-SQL живет в `company.yaml`
- Одна логическая фича = один persist query
- Query лучше делать идемпотентным (`INSERT ... ON DUPLICATE KEY UPDATE`)
- Если фича опциональна, управляйте ей через `persist_disabled_queries`

## 8) Пример Cisco port-security

Cisco enricher может и сохранить читаемые поля в порту, и зарегистрировать persist-операцию:

```go
p["psec_status"] = 1
p["psec_mac_limit"] = 32
snmp.AddPortPersistOp(p, "upsert_port_security", map[string]any{
	"psec_status": 1,
	"psec_mac_limit": 32,
})
```
