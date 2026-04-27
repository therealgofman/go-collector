# YAML, шаблоны и named queries

Этот документ описывает, как в проекте устроены конфигурация через YAML и SQL-шаблоны через named queries.

## 1) Где что лежит

- `config/app.yaml`:
  - глобальные настройки приложения (`app.*`),
  - правила выбора SNMP-моделей (`snmp_switch_models`),
  - `database_templates` (например `charset` для DSN).
- `config/companies/<company>.yaml`:
  - параметры компании (`company`),
  - подключение к БД (`database`),
  - схема таблиц и полей (`schema`, `schema.field_mapping`),
  - SQL-шаблоны (`queries.<name>.template`),
  - опциональные параметры шаблонов (`queries.<name>.params`).

## 2) Идея named queries

В коде не хардкодятся конкретные SQL-строки. Вместо этого вызывается query по имени, а SQL рендерится из YAML.

Пример вызова из репозитория:

- `Repo.GetVLANRows()`
- `Repo.UpdatePort(...)`

Плюсы подхода:

- можно менять таблицы/поля и часть SQL без перекомпиляции;
- одна и та же логика persist работает для разных схем БД компаний;
- фичи можно включать/отключать на уровне конфигурации.

## 3) Как рендерится SQL

Рендер выполняется через `internal/config.QueryBuilder` с `pongo2`.

Контекст шаблона включает:

- `company` — раздел `company` из `companies/*.yaml`;
- `schema` — раздел `schema`;
- `field_mapping` — `schema.field_mapping`;
- `app` — раздел `app` из `app.yaml`;
- `queries.<name>.params` — статические параметры конкретного query;
- `bind` — runtime bind-параметры (для `:named` placeholders);
- `extra` — дополнительные переменные шаблона (например для `IN (...)`).

Есть фильтр `quote` для имен колонок:

```jinja2
{{ field_mapping.port.name | quote }}
```

Он оборачивает значение в обратные кавычки, что удобно для безопасной подстановки идентификаторов.

## 4) bind и extra: в чем разница

- `bind`:
  - идет в `NamedExec/NamedQuery` как параметры `:name`;
  - используется для значений данных (`switch_id`, `port_id`, `ifindex` и т.п.).
- `extra`:
  - участвует только в рендере текста SQL;
  - нужен для фрагментов, которые нельзя передать через bind напрямую (например `IN ({{ port_ids_in }})`).

Рекомендация: по максимуму использовать `bind`, а `extra` — только для структурных SQL-фрагментов.

## 5) Управление выполнением запросов

На уровне компании поддерживается:

- `company.persist_disabled_queries: [query_name, ...]`

Если query входит в этот список, persist-слой пропускает его выполнение.

Дополнительно поддерживается legacy-флаг:

- `company.update_sysname_snmp: false`

Он эквивалентен отключению `update_switch_sysname_snmp`.

## 6) Как это связано с persist

`internal/db/persist/service.go` использует named queries как контракт:

- интерфейсы:
  - `update_port`, `insert_port`,
  - `delete_port2vlan_by_port`, `insert_port2vlan`,
  - плюс per-port операции из `port["persist"]` (например `upsert_port_security`);
- ARP:
  - `update_arp_table`, справочники `get_vlans`, `get_vrf_map`;
- MAC:
  - `upsert_mac_forward`,
  - `mark_mac_obsolete_global` / `mark_mac_obsolete_by_vlan`,
  - служебные селекты контекста.

То есть persist знает имена запросов и bind-контракт, но конкретный SQL определяется YAML.

## 7) Минимальный шаблон query

```yaml
queries:
  update_port:
    template: |
      UPDATE {{ schema.port_table }}
      SET {{ field_mapping.port.name | quote }} = :name
      WHERE {{ field_mapping.port.id | quote }} = :port_id
```

## 8) Рекомендации по шаблонам

- Имена query делать стабильными и осмысленными (`update_port`, `upsert_mac_forward`, `upsert_port_<feature>`).
- Для upsert-сценариев использовать идемпотентный SQL (`INSERT ... ON DUPLICATE KEY UPDATE`).
- Не смешивать бизнес-логику и SQL-диалект в Go-коде, держать SQL в `companies/*.yaml`.
- Избегать передачи пользовательского ввода в `extra`; если нужно, формировать `extra` в коде из проверенных данных.
- При добавлении новой фичи сначала зафиксировать bind-контракт в persist/enricher, затем добавить query в YAML.

## 9) Связанные документы

- Общая архитектура: `docs/architecture-overview.md`
- Поток enrich/persist интерфейсов: `docs/interface-enrichment-flow.md`

## 10) Батчевый режим для больших инвентарей

В `main` поддерживается флаг `-poll-batch-size` (по умолчанию `1000`):

- свитчи режутся на батчи;
- SNMP poll + persist выполняются по батчу;
- для MAC DB-контекст собирается только для текущего батча.

Это нужно, чтобы на больших объёмах не держать в памяти все `PollResult` сразу и не создавать избыточную пиковую нагрузку на БД.
