// Package config загружает YAML (app.yaml, companies/<код>.yaml) и собирает SQL через шаблоны pongo2.
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

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
