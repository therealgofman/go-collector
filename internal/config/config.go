// Package config загружает YAML (app.yaml, companies/<код>.yaml) и собирает SQL через шаблоны pongo2.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/flosch/pongo2/v6"
	"gopkg.in/yaml.v3"
)

// AppConfig — корень app.yaml (произвольная структура для Get/шаблонов).
type AppConfig struct {
	Root map[string]any
}

// CompanyConfig — одна компания: company, database, schema, именованные SQL-шаблоны queries.
type CompanyConfig struct {
	Company  map[string]any `yaml:"company"`
	Database map[string]any `yaml:"database"`
	Schema   map[string]any `yaml:"schema"`
	Queries  map[string]struct {
		Template string         `yaml:"template"`
		Params   map[string]any `yaml:"params"`
	} `yaml:"queries"`
}

// Loader читает файлы из каталога ConfigDir.
type Loader struct {
	ConfigDir string
}

// NewLoader создаёт загрузчик; все пути строятся относительно ConfigDir.
func NewLoader(configDir string) *Loader {
	return &Loader{ConfigDir: configDir}
}

// LoadAppConfig читает app.yaml в память как map (глобальные правила моделей, шаблоны БД, app.snmp.*).
func (l *Loader) LoadAppConfig() (*AppConfig, error) {
	p := filepath.Join(l.ConfigDir, "app.yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	return &AppConfig{Root: root}, nil
}

// LoadCompany загружает companies/<code>.yaml: схему таблиц, field_mapping, именованные SQL-шаблоны queries.
func (l *Loader) LoadCompany(code string) (*CompanyConfig, error) {
	p := filepath.Join(l.ConfigDir, "companies", code+".yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var cfg CompanyConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Get возвращает вложенное значение по пути вида "app.snmp.retries", как удобный доступ к YAML без жёсткой структуры.
func (a *AppConfig) Get(path string, def any) any {
	cur := any(a.Root)
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return def
		}
		next, ok := m[part]
		if !ok {
			return def
		}
		cur = next
	}
	return cur
}

// AppSection возвращает карту app: из корня (для шаблонов pongo2 и вывода name/version в CLI).
func (a *AppConfig) AppSection() map[string]any {
	v, _ := a.Root["app"].(map[string]any)
	return v
}

// DatabaseTemplate возвращает запись database_templates.<name> (charset и др. для сборки DSN и наследования в company).
func (a *AppConfig) DatabaseTemplate(name string) map[string]any {
	root, _ := a.Root["database_templates"].(map[string]any)
	v, _ := root[name].(map[string]any)
	return v
}

// IsPersistQueryEnabled проверяет, разрешён ли именованный SQL-шаг при persist (persist_disabled_queries, update_sysname_snmp).
func (c *CompanyConfig) IsPersistQueryEnabled(name string) bool {
	raw, ok := c.Company["persist_disabled_queries"]
	if ok {
		if arr, ok := raw.([]any); ok {
			for _, v := range arr {
				if fmt.Sprint(v) == name {
					return false
				}
			}
		}
	}
	if name == "update_switch_sysname_snmp" {
		if v, ok := c.Company["update_sysname_snmp"]; ok && v == false {
			return false
		}
	}
	return true
}

// DBURL собирает строку подключения для github.com/go-sql-driver/mysql из company.database и шаблона charset.
func (c *CompanyConfig) DBURL(a *AppConfig) (string, error) {
	tplName := fmt.Sprint(c.Company["db_template"])
	if tplName == "" {
		tplName = "mysql_default"
	}
	tpl := a.DatabaseTemplate(tplName)

	getS := func(m map[string]any, key, def string) string {
		if v, ok := m[key]; ok && fmt.Sprint(v) != "" {
			return fmt.Sprint(v)
		}
		return def
	}
	host := getS(c.Database, "host", "")
	port := getS(c.Database, "port", "3306")
	user := getS(c.Database, "user", "")
	pass := getS(c.Database, "password", "")
	dbn := getS(c.Database, "name", "")
	charset := getS(c.Database, "charset", getS(tpl, "charset", "utf8mb4"))
	if host == "" || user == "" || dbn == "" {
		return "", fmt.Errorf("настройки БД неполные")
	}
	// Только MySQL (github.com/go-sql-driver/mysql).
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=%s", user, pass, host, port, dbn, charset), nil
}

// QueryBuilder рендерит именованные запросы из YAML через pongo2.
type QueryBuilder struct {
	Company *CompanyConfig
	App     *AppConfig
}

// NewQueryBuilder связывает конфиг компании и app для контекста шаблонов.
func NewQueryBuilder(company *CompanyConfig, app *AppConfig) *QueryBuilder {
	return &QueryBuilder{Company: company, App: app}
}

var compactWS = regexp.MustCompile(`\s+`)
var registerFiltersOnce sync.Once

// Build находит queries.<name>, подставляет company, schema, field_mapping, app, params, bind и extra,
// регистрирует фильтр quote для имён столбцов и сжимает пробелы в итоговом SQL.
func (q *QueryBuilder) Build(name string, bind map[string]any, extra map[string]any) (string, error) {
	entry, ok := q.Company.Queries[name]
	if !ok {
		return "", fmt.Errorf("запрос %q не найден", name)
	}
	ctx := pongo2.Context{
		"company":       q.Company.Company,
		"schema":        q.Company.Schema,
		"field_mapping": q.Company.Schema["field_mapping"],
		"app":           q.App.AppSection(),
	}
	for k, v := range entry.Params {
		ctx[k] = v
	}
	for k, v := range bind {
		ctx[k] = v
	}
	for k, v := range extra {
		ctx[k] = v
	}
	registerFiltersOnce.Do(func() {
		_ = pongo2.RegisterFilter("quote", func(in *pongo2.Value, _ *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
			return pongo2.AsValue("`" + in.String() + "`"), nil
		})
	})
	tpl, err := pongo2.FromString(entry.Template)
	if err != nil {
		return "", err
	}
	out, err := tpl.Execute(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(compactWS.ReplaceAllString(out, " ")), nil
}
