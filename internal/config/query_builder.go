package config

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/flosch/pongo2/v6"
)

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
