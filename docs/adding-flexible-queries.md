# Как добавить новый гибкий query (YAML + код)

Этот гайд описывает практический поток добавления нового named query в текущей архитектуре:

- `Repository` — типизированный слой;
- `templated_store` — слой динамики шаблонов;
- SQL хранится в `config/companies/<company>.yaml`.

## 1) Добавьте query в `companies/<company>.yaml`

Пример:

```yaml
queries:
  update_port_note:
    template: |
      UPDATE {{ schema.table_port | quote }}
      SET {{ field_mapping.port.note | quote }} = :note
      WHERE {{ field_mapping.port.id | quote }} = :port_id
      {% if force_update %}
      AND 1 = 1
      {% endif %}
    params:
      force_update: false
```

Что важно:

- `:note`, `:port_id` — bind-переменные для `NamedExec`.
- `params` — дефолтные шаблонные параметры.
- Для структурной гибкости используйте шаблонные условия (`if`, `for`) и `params/extra`.

## 2) Добавьте typed bind-структуру в `repository.go`

```go
type bindPortNote struct {
    PortID int    `db:"port_id"`
    Note   string `db:"note"`
}
```

Правило: ключ `db` должен совпадать с плейсхолдером `:name` в SQL.

## 3) Добавьте метод в `Repository`

```go
func (r *Repository) UpdatePortNote(portID int, note string, extra map[string]string) error {
    if r.Readonly {
        return fmt.Errorf("readonly")
    }
    bind := bindPortNote{
        PortID: portID,
        Note:   note,
    }
    _, err := r.store.exec("update_port_note", bind, extra)
    return err
}
```

Рекомендации:

- для данных используйте typed `bind`;
- `extra` передавайте только когда реально нужна гибкость шаблона;
- если гибкость не нужна — передавайте `nil`.

## 4) Для SELECT используйте typed row-структуры

Поток для селектов:

1. Query в YAML (`get_*`).
2. Typed bind-структура (если нужны входные параметры).
3. В методе репозитория:
   - `rows, err := r.store.query("get_xxx", bind, extra)`
   - `StructScan` в typed `dbRow` с `sql.Null*` полями при необходимости.
4. Явное преобразование в доменный тип.

Минимальный пример:

```go
type getPortNoteRow struct {
    Note sql.NullString `db:"note"`
}
```

## 5) Как понять, что нужно в bind, а что в extra

- `bind`:
  - значения данных;
  - всё, что можно безопасно передать через `:named` placeholders.
- `extra`:
  - только шаблонные флаги/фрагменты SQL;
  - например условия, динамические блоки, заранее подготовленные выражения.

Практическое правило: сначала пытайтесь сделать через `bind`, `extra` используйте как исключение.

## 6) Чеклист перед коммитом

- query добавлен во все нужные `companies/*.yaml` (или есть fallback);
- `db`-теги bind-структур совпадают с `:named` в шаблоне;
- `readonly`-проверка есть для mutating-методов;
- `go test ./...` проходит.

