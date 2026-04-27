package db

import (
	"fmt"
	"reflect"

	"go-collector/internal/config"

	"github.com/jmoiron/sqlx"
)

// templatedStore — адаптер между typed-репозиторием и шаблонизатором SQL.
//
// Идея: Repository работает с типизированными структурами, а вся динамика
// (map-контекст, reflection, подстановка extra-параметров для шаблонов)
// локализована только в этом файле.
type templatedStore struct {
	db *sqlx.DB
	qb *config.QueryBuilder
}

func newTemplatedStore(db *sqlx.DB, qb *config.QueryBuilder) *templatedStore {
	return &templatedStore{db: db, qb: qb}
}

// toTemplateMap приводит bind/extra к виду map[string]any, который
// ожидает QueryBuilder.
//
// Поддерживаемые входы:
// - nil -> пустая map
// - map[string]any
// - map[string]string
// - struct / *struct (ключи берутся из `db`-тега, иначе из имени поля)
//
// Неподдерживаемые типы возвращают ошибку сразу, чтобы проблемы были явными.
func toTemplateMap(v any) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	if m, ok := v.(map[string]any); ok {
		return m, nil
	}
	if m, ok := v.(map[string]string); ok {
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[k] = val
		}
		return out, nil
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return map[string]any{}, nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("unsupported bind type %T", v)
	}
	rt := rv.Type()
	out := make(map[string]any, rv.NumField())
	for i := 0; i < rv.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		key := f.Tag.Get("db")
		if key == "" {
			key = f.Name
		}
		out[key] = rv.Field(i).Interface()
	}
	return out, nil
}

// build собирает финальный SQL по имени шаблона и возвращает bindMap для
// NamedExec/NamedQuery.
//
// Поток данных:
// typed bind/extra -> toTemplateMap -> qb.Build(...) -> sql + bindMap.
func (s *templatedStore) build(name string, bind any, extra any) (string, map[string]any, error) {
	bindMap, err := toTemplateMap(bind)
	if err != nil {
		return "", nil, err
	}
	extraMap, err := toTemplateMap(extra)
	if err != nil {
		return "", nil, err
	}
	sql, err := s.qb.Build(name, bindMap, extraMap)
	if err != nil {
		return "", nil, fmt.Errorf("build %s: %w", name, err)
	}
	return sql, bindMap, nil
}

// query рендерит SQL-шаблон и выполняет именованный SELECT.
//
// Unsafe() нужен из-за вариативности SELECT-колонок между компаниями:
// Repository.StructScan берёт нужные поля, лишние игнорируются.
func (s *templatedStore) query(name string, bind any, extra any) (*sqlx.Rows, error) {
	sql, bindMap, err := s.build(name, bind, extra)
	if err != nil {
		return nil, err
	}
	return s.db.Unsafe().NamedQuery(sql, bindMap)
}

// exec рендерит SQL-шаблон и выполняет именованный DML/DDL-запрос.
// Возвращает RowsAffected для единообразной статистики persist-операций.
func (s *templatedStore) exec(name string, bind any, extra any) (int64, error) {
	sql, bindMap, err := s.build(name, bind, extra)
	if err != nil {
		return 0, err
	}
	res, err := s.db.NamedExec(sql, bindMap)
	if err != nil {
		return 0, err
	}
	aff, _ := res.RowsAffected()
	return aff, nil
}

// insertLastID — вариант exec для INSERT, когда вызывающему нужен LastInsertId.
// Если драйвер не возвращает id, сохраняем прежнее поведение: 0, nil.
func (s *templatedStore) insertLastID(name string, bind any, extra any) (int64, error) {
	sql, bindMap, err := s.build(name, bind, extra)
	if err != nil {
		return 0, err
	}
	res, err := s.db.NamedExec(sql, bindMap)
	if err != nil {
		return 0, err
	}
	last, err := res.LastInsertId()
	if err != nil {
		return 0, nil
	}
	return last, nil
}
