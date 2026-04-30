// Package db содержит репозиторий SQL-запросов.
package db

import (
	"database/sql"
	"fmt"
	"strings"

	"go-collector/internal/config"
	"go-collector/internal/snmp"

	"github.com/jmoiron/sqlx"
)

// Repository выполняет SQL-запросы; подключение и зависимости передаются через DI.
type Repository struct {
	DB       *sqlx.DB
	Company  *config.CompanyConfig
	App      *config.AppConfig
	QB       *config.QueryBuilder
	store    *templatedStore
	Readonly bool
}

// Deps описывает зависимости репозитория для явного DI.
type Deps struct {
	DB      *sqlx.DB
	Company *config.CompanyConfig
	App     *config.AppConfig
	QB      *config.QueryBuilder
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

type bindPort struct {
	PortID      int    `db:"port_id"`
	Name        string `db:"name"`
	Trunk       int    `db:"trunk"`
	Description string `db:"description"`
	Disabled    int    `db:"disabled"`
	IfIndex     int    `db:"ifindex"`
}

type bindInsertPort struct {
	SwitchID    int    `db:"switch_id"`
	Trunk       int    `db:"trunk"`
	Name        string `db:"name"`
	Description string `db:"description"`
	IfIndex     int    `db:"ifindex"`
	Role        string `db:"role"`
}

type bindPortID struct {
	PortID int `db:"port_id"`
}

type bindPortVLAN struct {
	PortID int `db:"port_id"`
	VLANID int `db:"vlan_id"`
}

type bindARPTable struct {
	VRFID    int    `db:"vrf_id"`
	IP       string `db:"ip"`
	MAC      uint64 `db:"mac"`
	VLANID   int    `db:"vlan_id"`
	SwitchID int    `db:"switch_id"`
}

type bindSwitchSysname struct {
	SwitchID    int    `db:"switch_id"`
	SysnameSNMP string `db:"sysname_snmp"`
}

type bindMACForward struct {
	PortID int    `db:"port_id"`
	VLANID int    `db:"vlan_id"`
	MAC    uint64 `db:"mac"`
	Status int    `db:"sta"`
}

type bindPersistHook struct {
	SwitchID    int    `db:"switch_id"`
	PortID      int    `db:"port_id"`
	IfIndex     int    `db:"ifindex"`
	Name        string `db:"name"`
	Trunk       int    `db:"trunk"`
	Description string `db:"description"`
	Disabled    int    `db:"disabled"`
}

type bindBoundary struct {
	BoundaryBefore int `db:"boundary_before"`
}

type bindBoundaryVLAN struct {
	BoundaryBefore int `db:"boundary_before"`
	VLANID         int `db:"vlan_id"`
}

type bindPortIDsIn struct {
	PortIDsIn string `db:"port_ids_in"`
}

type bindSwitchID struct {
	SwitchID int `db:"switch_id"`
}

type bindSwitchIfIndex struct {
	SwitchID int `db:"switch_id"`
	IfIndex  int `db:"ifindex"`
}

type bindSwitchName struct {
	SwitchID int    `db:"switch_id"`
	Name     string `db:"name"`
}

func nullIntToInt(v sql.NullInt64) int {
	if !v.Valid {
		return 0
	}
	return int(v.Int64)
}

// NewRepository создаёт репозиторий из внешне переданных зависимостей.
func NewRepository(deps Deps) (*Repository, error) {
	if deps.DB == nil {
		return nil, fmt.Errorf("nil db")
	}
	if deps.Company == nil {
		return nil, fmt.Errorf("nil company config")
	}
	if deps.App == nil {
		return nil, fmt.Errorf("nil app config")
	}
	qb := deps.QB
	if qb == nil {
		qb = config.NewQueryBuilder(deps.Company, deps.App)
	}
	r := &Repository{
		DB:       deps.DB,
		Company:  deps.Company,
		App:      deps.App,
		QB:       qb,
		store:    newTemplatedStore(deps.DB, qb),
		Readonly: deps.Company.Database.Readonly,
	}
	return r, nil
}

func (r *Repository) UpdatePort(portID int, name string, trunk int, description string, disabled int, ifindex int, extra map[string]string) error {
	port := bindPort{
		PortID:      portID,
		Name:        name,
		Trunk:       trunk,
		Description: description,
		Disabled:    disabled,
		IfIndex:     ifindex,
	}
	if r.Readonly {
		return fmt.Errorf("readonly")
	}
	_, err := r.store.exec("update_port", port, extra)
	return err
}

func (r *Repository) InsertPort(switchID int, trunk int, name string, description string, ifindex int, role string, extra map[string]string) (int, error) {
	port := bindInsertPort{
		SwitchID:    switchID,
		Trunk:       trunk,
		Name:        name,
		Description: description,
		IfIndex:     ifindex,
		Role:        role,
	}
	if r.Readonly {
		return 0, fmt.Errorf("readonly")
	}
	last, err := r.store.insertLastID("insert_port", port, extra)
	if err != nil {
		return 0, err
	}
	return int(last), nil
}

func (r *Repository) DeletePort2VLANByPort(portID int) error {
	if r.Readonly {
		return fmt.Errorf("readonly")
	}
	_, err := r.store.exec("delete_port2vlan_by_port", bindPortID{PortID: portID}, nil)
	return err
}

func (r *Repository) InsertPort2VLAN(portID int, vlanID int) error {
	if r.Readonly {
		return fmt.Errorf("readonly")
	}
	_, err := r.store.exec("insert_port2vlan", bindPortVLAN{PortID: portID, VLANID: vlanID}, nil)
	return err
}

func (r *Repository) UpdateARPTable(vrfID int, ip string, mac uint64, vlanID int, switchID int) (int64, error) {
	if r.Readonly {
		return 0, fmt.Errorf("readonly")
	}
	return r.store.exec("update_arp_table", bindARPTable{
		VRFID: vrfID, IP: ip, MAC: mac, VLANID: vlanID, SwitchID: switchID,
	}, nil)
}

func (r *Repository) UpdateSwitchSysnameSNMP(switchID int, sysname string) error {
	if r.Readonly {
		return fmt.Errorf("readonly")
	}
	_, err := r.store.exec("update_switch_sysname_snmp", bindSwitchSysname{SwitchID: switchID, SysnameSNMP: sysname}, nil)
	return err
}

func (r *Repository) UpsertMACForward(portID int, vlanID int, mac uint64, sta int) (int64, error) {
	if r.Readonly {
		return 0, fmt.Errorf("readonly")
	}
	return r.store.exec("upsert_mac_forward", bindMACForward{PortID: portID, VLANID: vlanID, MAC: mac, Status: sta}, nil)
}

func (r *Repository) ExecPortPersistHook(query string, switchID int, portID int, ifindex int, name string, trunk int, description string, disabled int, params map[string]string) error {
	bind := bindPersistHook{
		SwitchID: switchID, PortID: portID, IfIndex: ifindex, Name: name,
		Trunk: trunk, Description: description, Disabled: disabled,
	}
	if r.Readonly {
		return fmt.Errorf("readonly")
	}
	_, err := r.store.exec(query, bind, params)
	return err
}

func (r *Repository) MarkMACObsoleteGlobal(boundaryBefore int, portIDsIn string) (int64, error) {
	if r.Readonly {
		return 0, fmt.Errorf("readonly")
	}
	return r.store.exec(
		"mark_mac_obsolete_global",
		bindBoundary{BoundaryBefore: boundaryBefore},
		bindPortIDsIn{PortIDsIn: portIDsIn},
	)
}

func (r *Repository) MarkMACObsoleteByVLAN(boundaryBefore int, vlanID int, portIDsIn string) (int64, error) {
	if r.Readonly {
		return 0, fmt.Errorf("readonly")
	}
	return r.store.exec(
		"mark_mac_obsolete_by_vlan",
		bindBoundaryVLAN{BoundaryBefore: boundaryBefore, VLANID: vlanID},
		bindPortIDsIn{PortIDsIn: portIDsIn},
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

func sanitizeDBString(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
}

func (r *Repository) getSwitchRows(name string, switchID *int) ([]snmp.SwitchRow, error) {
	// В шаблонах компаний могут быть дополнительные поля (например model_id):
	// Unsafe позволяет StructScan читать нужные колонки и игнорировать остальные.
	var (
		rows *sqlx.Rows
		err  error
	)
	if switchID != nil {
		rows, err = r.store.query(name, bindSwitchID{SwitchID: *switchID}, nil)
	} else {
		rows, err = r.store.query(name, nil, nil)
	}
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
	portRows, err := r.GetIfIndexToPortIDRows(switchID)
	if err == nil {
		fillIfIndexToPortID(ctx, portRows)
	}
	untaggedRows, err := r.GetIfIndexToUntaggedVLANRows(switchID)
	if err == nil {
		fillIfIndexToUntaggedVLAN(ctx, untaggedRows)
	}
	idxcomRows, err := r.GetIdxcomVLANRows(switchID)
	if err == nil {
		fillIdxcomVLANWalks(ctx, idxcomRows)
	}
	return ctx, nil
}

func fillIfIndexToPortID(ctx *snmp.MacDbContext, rows []IfIndexPortRow) {
	for _, row := range rows {
		if row.IfIndex > 0 && row.PortID > 0 {
			ctx.IfIndexToPortID[row.IfIndex] = row.PortID
		}
	}
}

func fillIfIndexToUntaggedVLAN(ctx *snmp.MacDbContext, rows []IfIndexVLANRow) {
	for _, row := range rows {
		if row.IfIndex > 0 && row.Number > 0 {
			ctx.IfIndexToUntaggedVLAN[row.IfIndex] = row.Number
		}
	}
}

func fillIdxcomVLANWalks(ctx *snmp.MacDbContext, rows []IdxcomVLANRow) {
	for _, row := range rows {
		if row.Number > 0 && row.VLANID > 0 {
			ctx.IdxcomVLANWalks = append(ctx.IdxcomVLANWalks, [2]int{row.Number, row.VLANID})
		}
	}
}

func (r *Repository) GetVLANRows() ([]VLANRow, error) {
	type vlanDBRow struct {
		DVLANID  sql.NullInt64  `db:"d_vlan_id"`
		VLANID   sql.NullInt64  `db:"vlan_id"`
		Number   sql.NullInt64  `db:"number"`
		DomainID sql.NullString `db:"domain_id"`
	}
	rows, err := r.store.query("get_vlans", nil, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]VLANRow, 0)
	for rows.Next() {
		var row vlanDBRow
		if err := rows.StructScan(&row); err != nil {
			return nil, err
		}
		vid := nullIntToInt(row.DVLANID)
		if vid == 0 {
			vid = nullIntToInt(row.VLANID)
		}
		if vid == 0 || !row.Number.Valid {
			continue
		}
		out = append(out, VLANRow{
			VLANID:   vid,
			Number:   int(row.Number.Int64),
			DomainID: sanitizeDBString(row.DomainID.String),
		})
	}
	return out, nil
}

func (r *Repository) GetVRFRows() ([]VRFRow, error) {
	type vrfDBRow struct {
		ID   sql.NullInt64  `db:"id"`
		Name sql.NullString `db:"name"`
	}
	rows, err := r.store.query("get_vrf_map", nil, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]VRFRow, 0)
	for rows.Next() {
		var row vrfDBRow
		if err := rows.StructScan(&row); err != nil {
			return nil, err
		}
		if !row.ID.Valid || row.ID.Int64 <= 0 {
			continue
		}
		name := sanitizeDBString(row.Name.String)
		if name == "" {
			continue
		}
		out = append(out, VRFRow{ID: int(row.ID.Int64), Name: name})
	}
	return out, nil
}

type portIDLookupRow struct {
	PortID  sql.NullInt64 `db:"port_id"`
	DPortID sql.NullInt64 `db:"d_port_id"`
}

func extractPortID(row portIDLookupRow) (int, bool) {
	id := nullIntToInt(row.PortID)
	if id == 0 {
		id = nullIntToInt(row.DPortID)
	}
	return id, id > 0
}

func (r *Repository) getPortIDByQuery(queryName string, bind any) (int, bool, error) {
	rows, err := r.store.query(queryName, bind, nil)
	if err != nil {
		return 0, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, false, nil
	}
	var row portIDLookupRow
	if err := rows.StructScan(&row); err != nil {
		return 0, false, err
	}
	id, ok := extractPortID(row)
	return id, ok, nil
}

func (r *Repository) GetPortIDByIfIndex(switchID, ifidx int) (int, bool, error) {
	return r.getPortIDByQuery("get_port_by_ifindex", bindSwitchIfIndex{SwitchID: switchID, IfIndex: ifidx})
}

func (r *Repository) GetPortIDByName(switchID int, name string) (int, bool, error) {
	return r.getPortIDByQuery("get_port_by_name", bindSwitchName{SwitchID: switchID, Name: name})
}

type IfIndexPortRow struct {
	IfIndex int
	PortID  int
}

func (r *Repository) GetIfIndexToPortIDRows(switchID int) ([]IfIndexPortRow, error) {
	type ifIndexPortDBRow struct {
		IfIndex sql.NullInt64 `db:"ifindex"`
		PortID  sql.NullInt64 `db:"port_id"`
		DPortID sql.NullInt64 `db:"d_port_id"`
	}
	rows, err := r.store.query("get_ifindex_to_port_id", bindSwitchID{SwitchID: switchID}, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IfIndexPortRow, 0)
	for rows.Next() {
		var row ifIndexPortDBRow
		if err := rows.StructScan(&row); err != nil {
			return nil, err
		}
		pid, _ := extractPortID(portIDLookupRow{PortID: row.PortID, DPortID: row.DPortID})
		out = append(out, IfIndexPortRow{
			IfIndex: nullIntToInt(row.IfIndex),
			PortID:  pid,
		})
	}
	return out, nil
}

type IfIndexVLANRow struct {
	IfIndex int
	Number  int
}

func (r *Repository) GetIfIndexToUntaggedVLANRows(switchID int) ([]IfIndexVLANRow, error) {
	type ifIndexVLANDBRow struct {
		IfIndex sql.NullInt64 `db:"ifindex"`
		Number  sql.NullInt64 `db:"number"`
	}
	rows, err := r.store.query("get_ifindex_untagged_vlan", bindSwitchID{SwitchID: switchID}, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IfIndexVLANRow, 0)
	for rows.Next() {
		var row ifIndexVLANDBRow
		if err := rows.StructScan(&row); err != nil {
			return nil, err
		}
		out = append(out, IfIndexVLANRow{
			IfIndex: nullIntToInt(row.IfIndex),
			Number:  nullIntToInt(row.Number),
		})
	}
	return out, nil
}

type IdxcomVLANRow struct {
	Number int
	VLANID int
}

func (r *Repository) GetIdxcomVLANRows(switchID int) ([]IdxcomVLANRow, error) {
	type idxcomVLANDBRow struct {
		Number  sql.NullInt64 `db:"number"`
		VLANID  sql.NullInt64 `db:"vlan_id"`
		DVLANID sql.NullInt64 `db:"d_vlan_id"`
	}
	rows, err := r.store.query("get_vlan_list_for_mac_idxcom", bindSwitchID{SwitchID: switchID}, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IdxcomVLANRow, 0)
	for rows.Next() {
		var row idxcomVLANDBRow
		if err := rows.StructScan(&row); err != nil {
			return nil, err
		}
		vid := nullIntToInt(row.VLANID)
		if vid == 0 {
			vid = nullIntToInt(row.DVLANID)
		}
		out = append(out, IdxcomVLANRow{
			Number: nullIntToInt(row.Number),
			VLANID: vid,
		})
	}
	return out, nil
}

func (r *Repository) GetSNMPTimestampBoundaryBefore() (int, error) {
	type tsRow struct {
		TS sql.NullInt64 `db:"ts"`
	}
	rows, err := r.store.query("get_snmp_timestamp_boundary", nil, nil)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, fmt.Errorf("empty get_snmp_timestamp_boundary")
	}
	var row tsRow
	if err := rows.StructScan(&row); err != nil {
		return 0, err
	}
	if !row.TS.Valid {
		return 0, fmt.Errorf("invalid ts in get_snmp_timestamp_boundary")
	}
	return int(row.TS.Int64), nil
}
