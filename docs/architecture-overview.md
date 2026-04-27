# Общая архитектура go-collector

Документ описывает верхнеуровневую архитектуру сервиса: от получения данных по SNMP до сохранения в БД.

## 1) Слои системы

- `internal/snmp` — получение и нормализация данных с устройств (vendor-specific collectors).
- `internal/snmp/models` — выбор модели устройства и сборка pipeline (factory + hooks).
- `internal/db`:
  - `connection.go` — инфраструктура подключения и ping БД,
  - `repository.go` — типизированный слой запросов,
  - `templated_store.go` — адаптер typed bind -> YAML SQL templates,
  - `persist` — orchestration сохранения результатов poll.
- `config/companies/*.yaml` — SQL-шаблоны и feature-флаги на уровне компании.

## 2) Поток данных (high-level)

1. По устройству выбирается модель в `internal/snmp/models/factory.go`.
2. Модель предоставляет collector-ы (например, по интерфейсам/VLAN).
3. Collector возвращает типизированные порты (`snmp.InterfacePorts`).
4. Опциональные enricher-ы добавляют поля и persist-операции в порты.
5. Persist-слой в `internal/db`:
   - upsert базовых данных порта,
   - синхронизирует связи `port2vlan`,
   - выполняет дополнительные named-query из `persist`.

## 3) SNMP слой

В `internal/snmp` используется общий `Client` и vendor-коллекторы:

- Cisco, D-Link, HPE, Huawei, SNR, Extreme и т.д. в `model_iface_*.go`.
- Общие helper-функции вынесены в `internal/helpers` для переиспользования между коллекторами.

Принцип: collector должен возвращать унифицированную структуру, а не SQL-логику.

## 4) Model factory и привязка логики

`internal/snmp/models/factory.go` определяет, какие collector/enricher использовать для конкретной модели.

Это основная точка расширения при добавлении нового вендора или новой фичи:

- новый `VendorIfaceCollector`,
- при необходимости новый `VendorIfaceEnricher`,
- подключение в factory.

## 5) Persist и SQL-конфигурация

Persist-слой универсален и не "знает" про конкретные фичи вендора. Он исполняет именованные запросы из `config/companies/<company>.yaml`.

Практически это дает:

- возможность добавлять фичи через enricher + YAML без переписывания ядра persist,
- управление фичами per-company через `persist_disabled_queries`,
- идемпотентные SQL-операции (`INSERT ... ON DUPLICATE KEY UPDATE`).

## 6) Формат портов как контракт

Базовый контракт порта:

- `InterfacePort.IfIndex`
- `InterfacePort.Name`
- `InterfacePort.Descr`
- `InterfacePort.Tagged`
- `InterfacePort.Disabled`
- `InterfacePort.VLANs`
- `InterfacePort.Persist` (опционально)

Важно сохранять обратную совместимость этого контракта, так как на него опираются enricher-ы и persist.

## 7) Точки расширения

- **Новый вендор/модель:** добавить collector в `internal/snmp`, зарегистрировать в factory.
- **Новая enrichment-фича:** добавить enricher, регистрировать через `NewIfaceCollectorWithEnrich`.
- **Новая запись в БД:** объявить named-query в `config/companies/<company>.yaml`, добавлять `PortPersistOp` в `InterfacePort.Persist`.

## 8) Масштабирование опроса

Для больших инвентарей (десятки/сотни тысяч устройств) `main` поддерживает батчевый режим:

- флаг `-poll-batch-size` управляет размером батча;
- SNMP-опрос и persist выполняются по батчам;
- таймаут одного batch настраивается через `app.snmp.poll_batch_timeout_s`;
- для MAC DB-контекст строится только для текущего батча.

Это снижает пик памяти и делает нагрузку на БД более предсказуемой.

### Практическая математика батчей

- **Размер батча:** `B = poll_batch_size` (CLI, default `1000`).
- **Число батчей:** `N = ceil(S / B)`, где `S` — число свитчей.
- **Воркеры на батч:** `W = min(poll_concurrency, batch_size)`.
- **Очереди в pipeline:** `jobs/results` буферизуются как `W * 4`.
- **Таймаут батча:** `T = app.snmp.poll_batch_timeout_s` (default `300s`).

Оценка длительности одного батча:

- грубо: `t_batch ≈ ceil(batch_size / W) * t_avg_one_switch`,
  где `t_avg_one_switch` — среднее время одного свитча для выбранного режима (`interfaces/arp/mac`).
- Для надёжности обычно задают `T` с запасом (например `p95`/`p99` по времени батча, а не среднее).

Пример:

- `S=12000`, `B=1000` -> `N=12` батчей.
- `poll_concurrency=20` -> `W=20` воркеров на полный батч.
- Если `t_avg_one_switch ≈ 2s`, то `t_batch ≈ ceil(1000/20)*2 = 100s`.
- Значит `T=300s` покрывает такой режим с запасом.

## 9) Связанные документы

- Поток enrich/persist: `docs/interface-enrichment-flow.md`
- YAML, шаблоны, named queries: `docs/yaml-templates-and-queries.md`
- Как добавлять новый гибкий query: `docs/adding-flexible-queries.md`
