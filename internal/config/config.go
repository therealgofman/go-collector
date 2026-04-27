// Package config загружает YAML (app.yaml, companies/<код>.yaml) и собирает SQL через шаблоны pongo2.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"go-collector/internal/snmp"

	"github.com/flosch/pongo2/v6"
	"gopkg.in/yaml.v3"
)

type AppSection struct {
	Name    string         `yaml:"name"`
	Version string         `yaml:"version"`
	SNMP    AppSNMP        `yaml:"snmp"`
	Raw     map[string]any `yaml:",inline"`
}

type AppSNMP struct {
	GetBulkMaxRepetitions int     `yaml:"getbulk_max_repetitions"`
	BulkMaxRepetitions    int     `yaml:"bulk_max_repetitions"`
	PollConcurrency       int     `yaml:"poll_concurrency"`
	PollBatchTimeoutS     float64 `yaml:"poll_batch_timeout_s"`
	ProgressIntervalS     float64 `yaml:"progress_interval_s"`
	TimeoutDefaultS       float64 `yaml:"timeout_default_s"`
	TimeoutMACS           float64 `yaml:"timeout_mac_s"`
	Retries               int     `yaml:"retries"`
}

type DatabaseTemplate struct {
	Charset string `yaml:"charset"`
}

// AppConfig — типизированная структура app.yaml.
type AppConfig struct {
	App               AppSection                  `yaml:"app"`
	SNMPSwitchModels  []snmp.ModelRule            `yaml:"snmp_switch_models"`
	DatabaseTemplates map[string]DatabaseTemplate `yaml:"database_templates"`
}

// CompanyConfig — одна компания: company, database, schema, именованные SQL-шаблоны queries.
type CompanyConfig struct {
	Company  CompanySection  `yaml:"company"`
	Database DatabaseSection `yaml:"database"`
	Schema   map[string]any  `yaml:"schema"`
	Queries  map[string]struct {
		Template string         `yaml:"template"`
		Params   map[string]any `yaml:"params"`
	} `yaml:"queries"`
}

type CompanySection struct {
	Name                   string         `yaml:"name"`
	DBTemplate             string         `yaml:"db_template"`
	PersistDisabledQueries []string       `yaml:"persist_disabled_queries"`
	UpdateSysnameSNMP      *bool          `yaml:"update_sysname_snmp"`
	Raw                    map[string]any `yaml:",inline"`
}

type DatabaseSection struct {
	Host     string         `yaml:"host"`
	Port     int            `yaml:"port"`
	Name     string         `yaml:"name"`
	User     string         `yaml:"user"`
	Password string         `yaml:"password"`
	Charset  string         `yaml:"charset"`
	Readonly bool           `yaml:"readonly"`
	Raw      map[string]any `yaml:",inline"`
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
	var cfg AppConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
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

// AppSectionMap возвращает app в map-виде для шаблонов pongo2.
func (a *AppConfig) AppSectionMap() map[string]any {
	out := map[string]any{
		"name":    a.App.Name,
		"version": a.App.Version,
	}
	for k, v := range a.App.Raw {
		out[k] = v
	}
	return out
}

// DatabaseTemplate возвращает запись database_templates.<name> (charset и др. для сборки DSN и наследования в company).
func (a *AppConfig) DatabaseTemplate(name string) DatabaseTemplate {
	return a.DatabaseTemplates[name]
}

func (a *AppConfig) SNMPSettings() AppSNMP {
	cfg := a.App.SNMP
	if cfg.GetBulkMaxRepetitions <= 0 {
		cfg.GetBulkMaxRepetitions = cfg.BulkMaxRepetitions
	}
	if cfg.GetBulkMaxRepetitions <= 0 {
		cfg.GetBulkMaxRepetitions = 10
	}
	if cfg.PollConcurrency <= 0 {
		cfg.PollConcurrency = 20
	}
	if cfg.TimeoutDefaultS <= 0 {
		cfg.TimeoutDefaultS = 5
	}
	if cfg.TimeoutMACS <= 0 {
		cfg.TimeoutMACS = cfg.TimeoutDefaultS
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	if cfg.ProgressIntervalS <= 0 {
		cfg.ProgressIntervalS = 30
	}
	if cfg.PollBatchTimeoutS <= 0 {
		cfg.PollBatchTimeoutS = 300
	}
	return cfg
}

// IsPersistQueryEnabled проверяет, разрешён ли именованный SQL-шаг при persist (persist_disabled_queries, update_sysname_snmp).
func (c *CompanyConfig) IsPersistQueryEnabled(name string) bool {
	for _, disabled := range c.Company.PersistDisabledQueries {
		if strings.TrimSpace(disabled) == name {
			return false
		}
	}
	if name == "update_switch_sysname_snmp" {
		if c.Company.UpdateSysnameSNMP != nil && !*c.Company.UpdateSysnameSNMP {
			return false
		}
	}
	return true
}

// DBURL собирает строку подключения для github.com/go-sql-driver/mysql из company.database и шаблона charset.
func (c *CompanyConfig) DBURL(a *AppConfig) (string, error) {
	tplName := strings.TrimSpace(c.Company.DBTemplate)
	if tplName == "" {
		tplName = "mysql_default"
	}
	tpl := a.DatabaseTemplate(tplName)
	getS := func(v, def string) string {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}
	host := getS(c.Database.Host, "")
	port := c.Database.Port
	if port <= 0 {
		port = 3306
	}
	user := getS(c.Database.User, "")
	pass := getS(c.Database.Password, "")
	dbn := getS(c.Database.Name, "")
	charset := getS(c.Database.Charset, getS(tpl.Charset, "utf8mb4"))
	if host == "" || user == "" || dbn == "" {
		return "", fmt.Errorf("настройки БД неполные")
	}
	// Только MySQL (github.com/go-sql-driver/mysql).
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=%s", user, pass, host, port, dbn, charset), nil
}

func (c *CompanySection) AsMap() map[string]any {
	out := map[string]any{
		"name":                     c.Name,
		"db_template":              c.DBTemplate,
		"persist_disabled_queries": c.PersistDisabledQueries,
	}
	if c.UpdateSysnameSNMP != nil {
		out["update_sysname_snmp"] = *c.UpdateSysnameSNMP
	}
	for k, v := range c.Raw {
		out[k] = v
	}
	return out
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
		"company":       q.Company.Company.AsMap(),
		"schema":        q.Company.Schema,
		"field_mapping": q.Company.Schema["field_mapping"],
		"app":           q.App.AppSectionMap(),
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
