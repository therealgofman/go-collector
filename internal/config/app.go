package config

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
