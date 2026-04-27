// Package db открывает пул MySQL через sqlx, строит SQL из YAML (QueryBuilder) и отдаёт строки/Exec для persist.
package db

import (
	"database/sql"
	"fmt"
	"strings"

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

type VLANRow struct {
	VLANID   int
	Number   int
	DomainID string
}

type VRFRow struct {
	ID   int
	Name string
}

func mapTypedRows[T any](rows []map[string]any, mapper func(map[string]any) (T, bool)) []T {
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		v, ok := mapper(row)
		if !ok {
			continue
		}
		out = append(out, v)
	}
	return out
}

func stringMapToAny(m map[string]string) map[string]any {
	if len(m) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
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

func (r *Repository) UpdatePort(portID int, name string, trunk int, description string, disabled int, ifindex int, extra map[string]string) error {
	bind := map[string]any{
		"port_id":     portID,
		"name":        name,
		"trunk":       trunk,
		"description": description,
		"disabled":    disabled,
		"ifindex":     ifindex,
	}
	for k, v := range extra {
		if _, exists := bind[k]; exists {
			continue
		}
		bind[k] = v
	}
	_, err := r.exec("update_port", bind, nil)
	return err
}

func (r *Repository) InsertPort(switchID int, trunk int, name string, description string, ifindex int, role string, extra map[string]string) (int, error) {
	bind := map[string]any{
		"switch_id":   switchID,
		"trunk":       trunk,
		"name":        name,
		"description": description,
		"ifindex":     ifindex,
		"role":        role,
	}
	for k, v := range extra {
		if _, exists := bind[k]; exists {
			continue
		}
		bind[k] = v
	}
	last, err := r.execInsertLastID("insert_port", bind, nil)
	if err != nil {
		return 0, err
	}
	return int(last), nil
}

func (r *Repository) DeletePort2VLANByPort(portID int) error {
	_, err := r.exec("delete_port2vlan_by_port", map[string]any{"port_id": portID}, nil)
	return err
}

func (r *Repository) InsertPort2VLAN(portID int, vlanID int) error {
	_, err := r.exec("insert_port2vlan", map[string]any{"port_id": portID, "vlan_id": vlanID}, nil)
	return err
}

func (r *Repository) UpdateARPTable(vrfID int, ip string, mac uint64, vlanID int, switchID int) (int64, error) {
	return r.exec("update_arp_table", map[string]any{
		"vrf_id": vrfID, "ip": ip, "mac": mac, "vlan_id": vlanID, "switch_id": switchID,
	}, nil)
}

func (r *Repository) UpdateSwitchSysnameSNMP(switchID int, sysname string) error {
	_, err := r.exec("update_switch_sysname_snmp", map[string]any{"switch_id": switchID, "sysname_snmp": sysname}, nil)
	return err
}

func (r *Repository) UpsertMACForward(portID int, vlanID int, mac uint64, sta int) (int64, error) {
	return r.exec("upsert_mac_forward", map[string]any{
		"port_id": portID, "vlan_id": vlanID, "mac": mac, "sta": sta,
	}, nil)
}

func (r *Repository) ExecPortPersistHook(query string, switchID int, portID int, ifindex int, name string, trunk int, description string, disabled int, params map[string]string) error {
	bind := map[string]any{
		"switch_id":   switchID,
		"port_id":     portID,
		"ifindex":     ifindex,
		"name":        name,
		"trunk":       trunk,
		"description": description,
		"disabled":    disabled,
	}
	for k, v := range stringMapToAny(params) {
		bind[k] = v
	}
	_, err := r.exec(query, bind, nil)
	return err
}

func (r *Repository) MarkMACObsoleteGlobal(boundaryBefore int, portIDsIn string) (int64, error) {
	return r.exec(
		"mark_mac_obsolete_global",
		map[string]any{"boundary_before": boundaryBefore},
		map[string]any{"port_ids_in": portIDsIn},
	)
}

func (r *Repository) MarkMACObsoleteByVLAN(boundaryBefore int, vlanID int, portIDsIn string) (int64, error) {
	return r.exec(
		"mark_mac_obsolete_by_vlan",
		map[string]any{"boundary_before": boundaryBefore, "vlan_id": vlanID},
		map[string]any{"port_ids_in": portIDsIn},
	)
}

type switchPollRow struct {
	DSwitchID sql.NullInt64 `db:"d_switch_id"`
	SwitchID  sql.NullInt64 `db:"switch_id"`
	IP        string        `db:"ip"`
	Comm      string        `db:"comm"`
	DomainID  string        `db:"domain_id"`
	HostName  string        `db:"host_name"`
}

func cleanSwitchField(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.TrimSpace(s)
}

func (r *Repository) getSwitchRows(name string, switchID *int) ([]snmp.SwitchRow, error) {
	bind := map[string]any{}
	if switchID != nil {
		bind["switch_id"] = *switchID
	}
	sqlText, err := r.QB.Build(name, bind, bind)
	if err != nil {
		return nil, err
	}
	// В шаблонах компаний могут быть дополнительные поля (например model_id):
	// Unsafe позволяет StructScan читать нужные колонки и игнорировать остальные.
	rows, err := r.DB.Unsafe().NamedQuery(sqlText, bind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]snmp.SwitchRow, 0)
	for rows.Next() {
		var row switchPollRow
		if err := rows.StructScan(&row); err != nil {
			return nil, err
		}
		id := 0
		if row.DSwitchID.Valid {
			id = int(row.DSwitchID.Int64)
		} else if row.SwitchID.Valid {
			id = int(row.SwitchID.Int64)
		}
		out = append(out, snmp.SwitchRow{
			ID:       id,
			IP:       cleanSwitchField(row.IP),
			Comm:     cleanSwitchField(row.Comm),
			DomainID: cleanSwitchField(row.DomainID),
			HostName: cleanSwitchField(row.HostName),
		})
	}
	return out, nil
}

// GetSwitchesForPoll возвращает список свитчей для опроса интерфейсов/MAC (шаблон get_switches_for_poll; switch_id опционален).
func (r *Repository) GetSwitchesForPoll(switchID *int) ([]snmp.SwitchRow, error) {
	return r.getSwitchRows("get_switches_for_poll", switchID)
}

// GetSwitchesForPollARP — свитчи для ARP-опроса (get_switches_for_poll_arp, join к модели и флагам do_arp/cap_arp).
func (r *Repository) GetSwitchesForPollARP(switchID *int) ([]snmp.SwitchRow, error) {
	return r.getSwitchRows("get_switches_for_poll_arp", switchID)
}

// BuildMACDBContext загружает для данного switch_id карты ifIndex→port, ifIndex→untagged VLAN и пары (vlan number, vlan_id) для режима idxcom
func (r *Repository) BuildMACDBContext(switchID int) (*snmp.MacDbContext, error) {
	ctx := &snmp.MacDbContext{
		IfIndexToPortID:       map[int]int{},
		IfIndexToUntaggedVLAN: map[int]int{},
		IdxcomVLANWalks:       [][2]int{},
	}
	a, err := r.GetIfIndexToPortIDRows(switchID)
	if err == nil {
		for _, row := range a {
			if row.IfIndex > 0 && row.PortID > 0 {
				ctx.IfIndexToPortID[row.IfIndex] = row.PortID
			}
		}
	}
	b, err := r.GetIfIndexToUntaggedVLANRows(switchID)
	if err == nil {
		for _, row := range b {
			if row.IfIndex > 0 && row.Number > 0 {
				ctx.IfIndexToUntaggedVLAN[row.IfIndex] = row.Number
			}
		}
	}
	c, err := r.GetIdxcomVLANRows(switchID)
	if err == nil {
		for _, row := range c {
			if row.Number > 0 && row.VLANID > 0 {
				ctx.IdxcomVLANWalks = append(ctx.IdxcomVLANWalks, [2]int{row.Number, row.VLANID})
			}
		}
	}
	return ctx, nil
}

func (r *Repository) GetVLANRows() ([]VLANRow, error) {
	rows, err := r.queryRows("get_vlans", nil)
	if err != nil {
		return nil, err
	}
	out := mapTypedRows(rows, func(row map[string]any) (VLANRow, bool) {
		vid, ok := helpers.FirstExistingInt(row, "d_vlan_id", "vlan_id")
		if !ok {
			return VLANRow{}, false
		}
		number, ok := helpers.AsInt(row["number"])
		if !ok {
			return VLANRow{}, false
		}
		return VLANRow{
			VLANID:   vid,
			Number:   number,
			DomainID: helpers.AsString(row["domain_id"]),
		}, true
	})
	return out, nil
}

func (r *Repository) GetVRFRows() ([]VRFRow, error) {
	rows, err := r.queryRows("get_vrf_map", nil)
	if err != nil {
		return nil, err
	}
	out := mapTypedRows(rows, func(row map[string]any) (VRFRow, bool) {
		id, ok := helpers.AsInt(row["id"])
		if !ok || id <= 0 {
			return VRFRow{}, false
		}
		name := helpers.AsString(row["name"])
		if name == "" {
			return VRFRow{}, false
		}
		return VRFRow{ID: id, Name: name}, true
	})
	return out, nil
}

func (r *Repository) GetPortIDByIfIndex(switchID, ifidx int) (int, bool, error) {
	rows, err := r.queryRows("get_port_by_ifindex", map[string]any{"switch_id": switchID, "ifindex": ifidx})
	if err != nil || len(rows) == 0 {
		return 0, false, err
	}
	for _, v := range rows[0] {
		n, ok := helpers.AsInt(v)
		return n, ok, nil
	}
	return 0, false, nil
}

func (r *Repository) GetPortIDByName(switchID int, name string) (int, bool, error) {
	rows, err := r.queryRows("get_port_by_name", map[string]any{"switch_id": switchID, "name": name})
	if err != nil || len(rows) == 0 {
		return 0, false, err
	}
	for _, v := range rows[0] {
		n, ok := helpers.AsInt(v)
		return n, ok, nil
	}
	return 0, false, nil
}

type IfIndexPortRow struct {
	IfIndex int
	PortID  int
}

func (r *Repository) GetIfIndexToPortIDRows(switchID int) ([]IfIndexPortRow, error) {
	rows, err := r.queryRows("get_ifindex_to_port_id", map[string]any{"switch_id": switchID})
	if err != nil {
		return nil, err
	}
	out := mapTypedRows(rows, func(row map[string]any) (IfIndexPortRow, bool) {
		ifi, _ := helpers.AsInt(row["ifindex"])
		pid, ok := helpers.FirstExistingInt(row, "port_id", "d_port_id")
		if !ok {
			pid = 0
		}
		return IfIndexPortRow{IfIndex: ifi, PortID: pid}, true
	})
	return out, nil
}

type IfIndexVLANRow struct {
	IfIndex int
	Number  int
}

func (r *Repository) GetIfIndexToUntaggedVLANRows(switchID int) ([]IfIndexVLANRow, error) {
	rows, err := r.queryRows("get_ifindex_untagged_vlan", map[string]any{"switch_id": switchID})
	if err != nil {
		return nil, err
	}
	out := mapTypedRows(rows, func(row map[string]any) (IfIndexVLANRow, bool) {
		ifi, _ := helpers.AsInt(row["ifindex"])
		number, _ := helpers.AsInt(row["number"])
		return IfIndexVLANRow{IfIndex: ifi, Number: number}, true
	})
	return out, nil
}

type IdxcomVLANRow struct {
	Number int
	VLANID int
}

func (r *Repository) GetIdxcomVLANRows(switchID int) ([]IdxcomVLANRow, error) {
	rows, err := r.queryRows("get_vlan_list_for_mac_idxcom", map[string]any{"switch_id": switchID})
	if err != nil {
		return nil, err
	}
	out := mapTypedRows(rows, func(row map[string]any) (IdxcomVLANRow, bool) {
		number, _ := helpers.AsInt(row["number"])
		vid, ok := helpers.FirstExistingInt(row, "vlan_id", "d_vlan_id")
		if !ok {
			vid = 0
		}
		return IdxcomVLANRow{Number: number, VLANID: vid}, true
	})
	return out, nil
}

func (r *Repository) GetSNMPTimestampBoundaryBefore() (int, error) {
	rows, err := r.queryRows("get_snmp_timestamp_boundary", nil)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, fmt.Errorf("empty get_snmp_timestamp_boundary")
	}
	v, ok := helpers.AsInt(rows[0]["ts"])
	if !ok {
		return 0, fmt.Errorf("invalid ts in get_snmp_timestamp_boundary")
	}
	return v, nil
}

