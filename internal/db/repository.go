// Package db открывает пул MySQL через sqlx, строит SQL из YAML (QueryBuilder) и отдаёт строки/Exec для persist.
package db

import (
	"fmt"

	"go-collector/internal/config"
	"go-collector/internal/helpers"
	"go-collector/internal/snmp"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

// Repository держит соединение, конфиг компании/app, билдер SQL и флаг readonly (database.readonly в yaml).
type Repository struct {
	DB       *sqlx.DB
	Company  *config.CompanyConfig
	App      *config.AppConfig
	QB       *config.QueryBuilder
	Readonly bool
}

// NewRepository собирает DSN, открывает mysql, проверяет get_ping, выставляет Readonly из company.Database["readonly"].
func NewRepository(company *config.CompanyConfig, app *config.AppConfig) (*Repository, error) {
	url, err := company.DBURL(app)
	if err != nil {
		return nil, err
	}
	db, err := sqlx.Open("mysql", url)
	if err != nil {
		return nil, err
	}
	r := &Repository{
		DB:       db,
		Company:  company,
		App:      app,
		QB:       config.NewQueryBuilder(company, app),
		Readonly: company.Database.Readonly,
	}
	if err := r.TestConnection(); err != nil {
		return nil, err
	}
	return r, nil
}

// Close закрывает пул соединений.
func (r *Repository) Close() error { return r.DB.Close() }

// TestConnection выполняет шаблон get_ping (SELECT 1) для проверки доступа к БД.
func (r *Repository) TestConnection() error {
	sql, err := r.QB.Build("get_ping", nil, nil)
	if err != nil {
		return err
	}
	var one int
	return r.DB.Get(&one, sql)
}

// queryRows выполняет именованный запрос без extra-контекста, сканирует строки в []map (байты → string).
func (r *Repository) queryRows(name string, bind map[string]any) ([]map[string]any, error) {
	if bind == nil {
		bind = map[string]any{}
	}
	sql, err := r.QB.Build(name, bind, nil)
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.NamedQuery(sql, bind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		m := map[string]any{}
		if err := rows.MapScan(m); err != nil {
			return nil, err
		}
		for k, v := range m {
			if b, ok := v.([]byte); ok {
				m[k] = string(b)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// QueryRows экспортирован для пакета persist и внешних вызовов с тем же контрактом, что queryRows.
func (r *Repository) QueryRows(name string, bind map[string]any) ([]map[string]any, error) {
	return r.queryRows(name, bind)
}

// queryRowsExtra строит SQL с дополнительным контекстом extra (например подстановка списков в IN (...)).
func (r *Repository) queryRowsExtra(name string, bind map[string]any, extra map[string]any) ([]map[string]any, error) {
	if bind == nil {
		bind = map[string]any{}
	}
	sql, err := r.QB.Build(name, bind, extra)
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.NamedQuery(sql, bind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		m := map[string]any{}
		if err := rows.MapScan(m); err != nil {
			return nil, err
		}
		for k, v := range m {
			if b, ok := v.([]byte); ok {
				m[k] = string(b)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// QueryRowsExtra экспортирован для persist.
func (r *Repository) QueryRowsExtra(name string, bind map[string]any, extra map[string]any) ([]map[string]any, error) {
	return r.queryRowsExtra(name, bind, extra)
}

// exec выполняет именованный не-SELECT запрос; при Readonly возвращает ошибку без обращения к БД.
func (r *Repository) exec(name string, bind map[string]any, extra map[string]any) (int64, error) {
	if r.Readonly {
		return 0, fmt.Errorf("readonly")
	}
	if bind == nil {
		bind = map[string]any{}
	}
	sql, err := r.QB.Build(name, bind, extra)
	if err != nil {
		return 0, err
	}
	res, err := r.DB.NamedExec(sql, bind)
	if err != nil {
		return 0, err
	}
	aff, _ := res.RowsAffected()
	return aff, nil
}

// Exec экспортирован для persist (учёт affected rows).
func (r *Repository) Exec(name string, bind map[string]any, extra map[string]any) (int64, error) {
	return r.exec(name, bind, extra)
}

// execInsertLastID выполняет INSERT и возвращает LastInsertId (для insert_port).
func (r *Repository) execInsertLastID(name string, bind map[string]any, extra map[string]any) (int64, error) {
	if r.Readonly {
		return 0, fmt.Errorf("readonly")
	}
	if bind == nil {
		bind = map[string]any{}
	}
	sql, err := r.QB.Build(name, bind, extra)
	if err != nil {
		return 0, err
	}
	res, err := r.DB.NamedExec(sql, bind)
	if err != nil {
		return 0, err
	}
	last, err := res.LastInsertId()
	if err != nil {
		return 0, nil
	}
	return last, nil
}

// ExecInsertLastID экспортирован для persist.
func (r *Repository) ExecInsertLastID(name string, bind map[string]any, extra map[string]any) (int64, error) {
	return r.execInsertLastID(name, bind, extra)
}

// GetSwitchesForPoll возвращает список свитчей для опроса интерфейсов/MAC (шаблон get_switches_for_poll; switch_id опционален).
func (r *Repository) GetSwitchesForPoll(switchID *int) ([]map[string]any, error) {
	bind := map[string]any{}
	if switchID != nil {
		bind["switch_id"] = *switchID
	}
	return r.queryRowsExtra("get_switches_for_poll", bind, bind)
}

// GetSwitchesForPollARP — свитчи для ARP-опроса (get_switches_for_poll_arp, join к модели и флагам do_arp/cap_arp).
func (r *Repository) GetSwitchesForPollARP(switchID *int) ([]map[string]any, error) {
	bind := map[string]any{}
	if switchID != nil {
		bind["switch_id"] = *switchID
	}
	return r.queryRowsExtra("get_switches_for_poll_arp", bind, bind)
}

// BuildMACDBContext загружает для данного switch_id карты ifIndex→port, ifIndex→untagged VLAN и пары (vlan number, vlan_id) для режима idxcom
func (r *Repository) BuildMACDBContext(switchID int) (*snmp.MacDbContext, error) {
	ctx := &snmp.MacDbContext{
		IfIndexToPortID:       map[int]int{},
		IfIndexToUntaggedVLAN: map[int]int{},
		IdxcomVLANWalks:       [][2]int{},
	}
	a, err := r.queryRows("get_ifindex_to_port_id", map[string]any{"switch_id": switchID})
	if err == nil {
		for _, row := range a {
			i, _ := helpers.AsInt(row["ifindex"])
			p, ok := helpers.FirstExistingInt(row, "port_id", "d_port_id")
			if !ok {
				p = 0
			}
			if i > 0 && p > 0 {
				ctx.IfIndexToPortID[i] = p
			}
		}
	}
	b, err := r.queryRows("get_ifindex_untagged_vlan", map[string]any{"switch_id": switchID})
	if err == nil {
		for _, row := range b {
			i, _ := helpers.AsInt(row["ifindex"])
			v, _ := helpers.AsInt(row["number"])
			if i > 0 && v > 0 {
				ctx.IfIndexToUntaggedVLAN[i] = v
			}
		}
	}
	c, err := r.queryRows("get_vlan_list_for_mac_idxcom", map[string]any{"switch_id": switchID})
	if err == nil {
		for _, row := range c {
			vn, _ := helpers.AsInt(row["number"])
			vid, ok := helpers.FirstExistingInt(row, "vlan_id", "d_vlan_id")
			if !ok {
				vid = 0
			}
			if vn > 0 && vid > 0 {
				ctx.IdxcomVLANWalks = append(ctx.IdxcomVLANWalks, [2]int{vn, vid})
			}
		}
	}
	return ctx, nil
}
