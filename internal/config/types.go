package config

import "go-collector/internal/snmp"

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
