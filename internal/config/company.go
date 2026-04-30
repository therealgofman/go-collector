package config

import (
	"fmt"
	"maps"
	"strings"
)

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
	maps.Copy(out, c.Raw)
	return out
}
