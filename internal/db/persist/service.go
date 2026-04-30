// Package persist записывает результаты SNMP в MySQL: интерфейсы/VLAN, ARP, MAC.
package persist

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go-collector/internal/db"
	"go-collector/internal/snmp"
)

// Service инкапсулирует сценарии сохранения поверх db.Repository (без дублирования SQL в вызывающем коде).
type Service struct {
	repo *db.Repository
}

// New создаёт сервис записи для переданного репозитория.
func New(repo *db.Repository) *Service { return &Service{repo: repo} }

type PersistInterfacesStats struct {
	Skipped           bool
	SwitchesProcessed int
	VLANLinks         int
	PrepareErrors     []string
}

type PersistARPStats struct {
	Skipped           bool
	RowsUpserted      int
	MySQLAffectedRows int64
	SwitchesProcessed int
	PrepareErrors     []string
}

type PersistMACStats struct {
	Skipped              bool
	RowsUpserted         int
	MySQLAffectedRows    int64
	ObsoleteRowsAffected int64
	SwitchesProcessed    int
	PrepareErrors        []string
}

type groupedMessage struct {
	msg   string
	count int
}

// renderTopTable рендерит простую таблицу "ключ -> количество".
func renderTopTable(header string, counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	type row struct {
		key   string
		count int
	}
	rows := make([]row, 0, len(counts))
	for k, c := range counts {
		rows = append(rows, row{key: k, count: c})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].key < rows[j].key
	})
	lines := []string{
		fmt.Sprintf("  %-28s | rows", header),
		"  ------------------------------+------",
	}
	for _, r := range rows {
		lines = append(lines, fmt.Sprintf("  %-28s | %d", r.key, r.count))
	}
	return "\n" + strings.Join(lines, "\n")
}

// summarizeMessages группирует одинаковые сообщения и добавляет префикс кратности.
func summarizeMessages(messages []string) []string {
	if len(messages) == 0 {
		return []string{}
	}
	counter := map[string]int{}
	for _, msg := range messages {
		counter[msg]++
	}
	grouped := make([]groupedMessage, 0, len(counter))
	for msg, count := range counter {
		grouped = append(grouped, groupedMessage{msg: msg, count: count})
	}
	sort.Slice(grouped, func(i, j int) bool {
		if grouped[i].count != grouped[j].count {
			return grouped[i].count > grouped[j].count
		}
		return grouped[i].msg < grouped[j].msg
	})
	out := make([]string, 0, len(grouped))
	for _, g := range grouped {
		out = append(out, fmt.Sprintf("(%dx) %s", g.count, g.msg))
	}
	return out
}

// normalizeMACToInt приводит MAC-строку к uint64 для полей БД в целочисленном виде.
func normalizeMACToInt(mac string) (uint64, error) {
	h := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(mac), "0x", ""), ":", ""), "-", ""))
	if len(h) != 12 {
		return 0, fmt.Errorf("invalid mac: %q", mac)
	}
	v, err := strconv.ParseUint(h, 16, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// buildVLANMaps строит карты номер VLAN → vlan_id: по доменам (domain_id) и глобальную для domain_id пустого/0
// из результата get_vlans.
func (p *Service) buildVLANMaps() (map[string]map[int]int, map[int]int, error) {
	rows, err := p.repo.GetVLANRows()
	if err != nil {
		return nil, nil, err
	}
	local := map[string]map[int]int{}
	global := map[int]int{}
	for _, row := range rows {
		vid := row.VLANID
		vnum := row.Number
		domKey := row.DomainID
		if domKey == "" || domKey == "0" {
			global[vnum] = vid
			continue
		}
		if _, ok := local[domKey]; !ok {
			local[domKey] = map[int]int{}
		}
		local[domKey][vnum] = vid
	}
	return local, global, nil
}

// resolveVLANID находит vlan_id по номеру VLAN и domain_id свитча.
func resolveVLANID(vlan int, domain string, local map[string]map[int]int, global map[int]int) (int, bool) {
	dk := strings.TrimSpace(domain)
	if m, ok := local[dk]; ok {
		if vid, ok := m[vlan]; ok {
			return vid, true
		}
	}
	vid, ok := global[vlan]
	return vid, ok
}

// splitVLANVRF разбирает ключ VLAN в ARP-таблице: "123" или "123@vrf_name".
func splitVLANVRF(key string) (int, string, bool) {
	raw := strings.TrimSpace(key)
	if raw == "" {
		return 0, "", false
	}
	vlan := raw
	vrf := ""
	if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		vlan = strings.TrimSpace(parts[0])
		vrf = strings.TrimSpace(parts[1])
	}
	v, err := strconv.Atoi(vlan)
	if err != nil {
		return 0, "", false
	}
	return v, vrf, true
}

// getVRFNameToID загружает отображение имя VRF → id из get_vrf_map.
func (p *Service) getVRFNameToID() (map[string]int, error) {
	rows, err := p.repo.GetVRFRows()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, row := range rows {
		out[row.Name] = row.ID
	}
	return out, nil
}

// parsedInterface — нормализованная строка интерфейса после poll (до SQL).
type parsedInterface struct {
	ifIndex     int
	name        string
	trunk       int
	description string
	disabled    int
	vlans       []int
	extraFields map[string]string
	persistOps  []parsedPortPersistOp
}

type parsedPortPersistOp struct {
	query string
	bind  map[string]string
}

type macPreparedRow struct {
	portID, vlanID int
	macInt         uint64
	sta            int
}

type portSyncResult struct {
	portID   int
	warnings []string
}

type macPersistDelta struct {
	rowsUpserted         int
	mysqlAffectedRows    int64
	obsoleteRowsAffected int64
	switchProcessed      bool
	warnings             []string
}

type interfacesPersistDelta struct {
	linksInserted   int
	switchProcessed bool
	warnings        []string
}

// parseInterfaces превращает typed InterfacePorts из CollectInterfaces в срез с отсортированным списком VLAN на порт.
func parseInterfaces(interfaces snmp.InterfacePorts) []parsedInterface {
	out := []parsedInterface{}
	for pkey, pdata := range interfaces {
		ifidx := pdata.IfIndex
		if ifidx <= 0 {
			if v, err := strconv.Atoi(strings.TrimSpace(pkey)); err == nil {
				ifidx = v
			}
		}
		trunk := 0
		if pdata.Tagged {
			trunk = 1
		}
		dis := 0
		if pdata.Disabled {
			dis = 1
		}
		name := pdata.Name
		if name == "" {
			name = pkey
		}
		vlans := make([]int, 0, len(pdata.VLANs))
		for k := range pdata.VLANs {
			vlans = append(vlans, k)
		}
		sort.Ints(vlans)
		persistOps := make([]parsedPortPersistOp, 0, len(pdata.Persist))
		for _, op := range pdata.Persist {
			persistOps = append(persistOps, parsedPortPersistOp{query: op.Query, bind: op.Params})
		}
		out = append(out, parsedInterface{
			ifIndex: ifidx, name: name, trunk: trunk, description: pdata.Descr, disabled: dis, vlans: vlans, extraFields: pdata.Extra, persistOps: persistOps,
		})
	}
	return out
}

// getPortByIfIndex ищет port_id по ifindex.
func (p *Service) getPortByIfIndex(switchID int, ifidx int) (int, bool) {
	id, ok, err := p.repo.GetPortIDByIfIndex(switchID, ifidx)
	if err != nil {
		return 0, false
	}
	return id, ok
}

// getPortByName ищет port_id по name.
func (p *Service) getPortByName(switchID int, name string) (int, bool) {
	id, ok, err := p.repo.GetPortIDByName(switchID, name)
	if err != nil {
		return 0, false
	}
	return id, ok
}

// fillTablesFromInterfaces обновляет или создаёт порты, синхронизирует port2vlan (delete + insert),
// возвращает число вставленных связей VLAN и предупреждения о неизвестных VLAN.
func (p *Service) fillTablesFromInterfaces(switchID int, interfaces snmp.InterfacePorts, domainID string, ip string, local map[string]map[int]int, global map[int]int) (int, []string, error) {
	count := 0
	warnings := []string{}
	for _, row := range parseInterfaces(interfaces) {
		syncRes, err := p.ensurePort(switchID, row, ip)
		if err != nil {
			return count, warnings, err
		}
		warnings = append(warnings, syncRes.warnings...)
		if syncRes.portID <= 0 {
			continue
		}
		hookWarnings, err := p.runPortPersistHooks(switchID, syncRes.portID, row, ip)
		if err != nil {
			return count, warnings, err
		}
		warnings = append(warnings, hookWarnings...)
		insertedLinks, vlanWarnings, err := p.syncPortVLANLinks(syncRes.portID, row, domainID, ip, local, global)
		if err != nil {
			return count, warnings, err
		}
		count += insertedLinks
		warnings = append(warnings, vlanWarnings...)
	}
	return count, warnings, nil
}

func (p *Service) ensurePort(switchID int, row parsedInterface, ip string) (portSyncResult, error) {
	pid, ok := p.getPortByIfIndex(switchID, row.ifIndex)
	if !ok {
		pid, ok = p.getPortByName(switchID, row.name)
	}
	if ok {
		if !p.repo.Company.IsPersistQueryEnabled("update_port") {
			return portSyncResult{portID: pid, warnings: []string{}}, nil
		}
		if err := p.repo.UpdatePort(pid, row.name, row.trunk, row.description, row.disabled, row.ifIndex, row.extraFields); err != nil {
			return portSyncResult{}, err
		}
		return portSyncResult{portID: pid, warnings: []string{}}, nil
	}
	if !p.repo.Company.IsPersistQueryEnabled("insert_port") {
		return portSyncResult{
			portID:   0,
			warnings: []string{fmt.Sprintf("%s: port %s: insert_port disabled in persist_disabled_queries, skipped", ip, row.name)},
		}, nil
	}
	role := "2"
	if row.trunk == 1 {
		role = "1"
	}
	inserted, err := p.repo.InsertPort(switchID, row.trunk, row.name, row.description, row.ifIndex, role, row.extraFields)
	if err != nil {
		return portSyncResult{}, err
	}
	return portSyncResult{portID: inserted, warnings: []string{}}, nil
}

func (p *Service) runPortPersistHooks(switchID int, portID int, row parsedInterface, ip string) ([]string, error) {
	warnings := []string{}
	for _, op := range row.persistOps {
		if op.query == "" {
			continue
		}
		if _, has := p.repo.Company.Queries[op.query]; !has {
			warnings = append(warnings, fmt.Sprintf("%s: port %s: persist query %s not found, skipped", ip, row.name, op.query))
			continue
		}
		if !p.repo.Company.IsPersistQueryEnabled(op.query) {
			warnings = append(warnings, fmt.Sprintf("%s: port %s: persist query %s disabled, skipped", ip, row.name, op.query))
			continue
		}
		if err := p.repo.ExecPortPersistHook(
			op.query,
			switchID,
			portID,
			row.ifIndex,
			row.name,
			row.trunk,
			row.description,
			row.disabled,
			op.bind,
		); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

func (p *Service) syncPortVLANLinks(
	portID int,
	row parsedInterface,
	domainID string,
	ip string,
	local map[string]map[int]int,
	global map[int]int,
) (int, []string, error) {
	warnings := []string{}
	canDelete := p.repo.Company.IsPersistQueryEnabled("delete_port2vlan_by_port")
	canInsert := p.repo.Company.IsPersistQueryEnabled("insert_port2vlan")

	if !canDelete {
		if len(row.vlans) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: port %s: VLAN sync skipped (delete_port2vlan_by_port disabled)", ip, row.name))
		}
		return 0, warnings, nil
	}
	if err := p.repo.DeletePort2VLANByPort(portID); err != nil {
		return 0, nil, err
	}
	if !canInsert {
		if len(row.vlans) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: port %s: insert_port2vlan disabled, VLAN links removed", ip, row.name))
		}
		return 0, warnings, nil
	}

	inserted := 0
	for _, vlanNum := range row.vlans {
		vid, ok := resolveVLANID(vlanNum, domainID, local, global)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("%s\tunknown vlan %d on port %s", ip, vlanNum, row.name))
			continue
		}
		if err := p.repo.InsertPort2VLAN(portID, vid); err != nil {
			return inserted, warnings, err
		}
		inserted++
	}
	return inserted, warnings, nil
}

// getSNMPPollBoundaryBefore читает метку времени «чуть раньше сейчас» — границу для пометки устаревших MAC (не попавших в текущий опрос).
func (p *Service) getSNMPPollBoundaryBefore() (int, error) {
	return p.repo.GetSNMPTimestampBoundaryBefore()
}

// markObsoleteMAC вызывает шаблоны mark_mac_obsolete_* из YAML: сбрасывает признак актуальности у записей старше границы.
func (p *Service) markObsoleteMAC(boundary int, portIDs []int, vlanID *int) (int64, error) {
	if len(portIDs) == 0 {
		return 0, nil
	}
	set := map[int]struct{}{}
	for _, id := range portIDs {
		if id > 0 {
			set[id] = struct{}{}
		}
	}
	uniq := make([]int, 0, len(set))
	for id := range set {
		uniq = append(uniq, id)
	}
	sort.Ints(uniq)
	parts := make([]string, 0, len(uniq))
	for _, id := range uniq {
		parts = append(parts, strconv.Itoa(id))
	}
	portIDsIn := strings.Join(parts, ",")
	if vlanID == nil {
		return p.repo.MarkMACObsoleteGlobal(boundary, portIDsIn)
	}
	return p.repo.MarkMACObsoleteByVLAN(boundary, *vlanID, portIDsIn)
}

func (p *Service) markObsoleteForMACRows(
	boundary int,
	prepared []macPreparedRow,
	portIDs []int,
	byVLAN bool,
	hostCtx string,
) (int64, string, error) {
	canGlobal := p.repo.Company.IsPersistQueryEnabled("mark_mac_obsolete_global")
	canByVLAN := p.repo.Company.IsPersistQueryEnabled("mark_mac_obsolete_by_vlan")

	if byVLAN {
		if !canByVLAN {
			return 0, hostCtx + ": режим пометки по VLAN (obsolete_by_vlan), но запрос mark_mac_obsolete_by_vlan отключён — пометка устаревших пропущена", nil
		}
		affected := int64(0)
		seen := map[int]struct{}{}
		for _, row := range prepared {
			if _, ok := seen[row.vlanID]; ok {
				continue
			}
			seen[row.vlanID] = struct{}{}
			v := row.vlanID
			aff, err := p.markObsoleteMAC(boundary, portIDs, &v)
			if err != nil {
				return 0, "", err
			}
			affected += aff
		}
		return affected, "", nil
	}

	if !canGlobal {
		return 0, hostCtx + ": запросы пометки устаревших отключены (persist_disabled_queries)", nil
	}
	aff, err := p.markObsoleteMAC(boundary, portIDs, nil)
	return aff, "", err
}

func buildFallbackCountersWarning(hostCtx string, fallback map[int]map[int]int) string {
	if len(fallback) == 0 {
		return ""
	}
	vlans := make([]int, 0, len(fallback))
	for v := range fallback {
		vlans = append(vlans, v)
	}
	sort.Ints(vlans)
	msg := fmt.Sprintf("%s: fallback VLAN counters from collector", hostCtx)
	for _, v := range vlans {
		table := map[string]int{}
		for ifidx, n := range fallback[v] {
			table[fmt.Sprintf("ifindex=%d", ifidx)] = n
		}
		msg += renderTopTable(fmt.Sprintf("vlan=%d", v), table)
	}
	return msg
}

func (p *Service) prepareMACRows(
	hostCtx string,
	pr snmp.PollResult,
	local map[string]map[int]int,
	global map[int]int,
) ([]macPreparedRow, []string) {
	prepared := []macPreparedRow{}
	warnings := []string{}
	for _, row := range pr.MacTable.Entries {
		pid := row.PortID
		if pid <= 0 {
			warnings = append(warnings, fmt.Sprintf("%s: no port_id (skip)", hostCtx))
			continue
		}

		vid := row.VLANID
		if vid <= 0 {
			vnum := row.VLAN
			if vnum <= 0 {
				warnings = append(warnings, fmt.Sprintf("%s: no vlan_id/vlan", hostCtx))
				continue
			}
			resolved, ok := resolveVLANID(vnum, pr.Switch.DomainID, local, global)
			if !ok {
				if vnum == 9999 {
					// Для fallback-9999 не дублируем построчными prepare_errors:
					// агрегат выводится из typed meta.FallbackVLANIfIndexCounts.
					continue
				}
				warnings = append(warnings, fmt.Sprintf("%s, vlan=%d, domain_id=%s: VLAN не найден в справочнике БД (resolveVLANID)", hostCtx, vnum, pr.Switch.DomainID))
				continue
			}
			vid = resolved
		}

		macInt, err := normalizeMACToInt(row.MAC)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: mac %q: %v", hostCtx, row.MAC, err))
			continue
		}
		prepared = append(prepared, macPreparedRow{portID: pid, vlanID: vid, macInt: macInt, sta: row.Status})
	}
	return prepared, warnings
}

// PersistARP записывает ARP: для каждого успешного результата разбирает VLAN/VRF, резолвит vlan_id, upsert в ip_arp.
// Ошибки подготовки отдельных строк попадают в prepare_errors; фатальные ошибки БД прерывают весь вызов.
func (p *Service) PersistARP(results []snmp.PollResult) (PersistARPStats, error) {
	if p.repo.Readonly {
		return PersistARPStats{Skipped: true, PrepareErrors: []string{}}, nil
	}
	if len(results) == 0 {
		return PersistARPStats{PrepareErrors: []string{}}, nil
	}
	local, global, err := p.buildVLANMaps()
	if err != nil {
		return PersistARPStats{}, err
	}
	vrfMap, err := p.getVRFNameToID()
	if err != nil {
		return PersistARPStats{}, err
	}
	stats := PersistARPStats{}
	prepareErrors := []string{}
	for _, pr := range results {
		rows, mysqlAffected, warns, err := p.persistARPSwitch(pr, local, global, vrfMap)
		if err != nil {
			return PersistARPStats{}, err
		}
		prepareErrors = append(prepareErrors, warns...)
		stats.RowsUpserted += rows
		stats.MySQLAffectedRows += mysqlAffected
	}
	stats.Skipped = false
	stats.SwitchesProcessed = len(results)
	stats.PrepareErrors = summarizeMessages(prepareErrors)
	return stats, nil
}

// PersistInterfaces обновляет sysname_snmp (если разрешено), для каждого свитча вызывает fillTablesFromInterfaces.
func (p *Service) PersistInterfaces(results []snmp.PollResult) (PersistInterfacesStats, error) {
	if p.repo.Readonly {
		return PersistInterfacesStats{Skipped: true, PrepareErrors: []string{}}, nil
	}
	if len(results) == 0 {
		return PersistInterfacesStats{PrepareErrors: []string{}}, nil
	}
	local, global, err := p.buildVLANMaps()
	if err != nil {
		return PersistInterfacesStats{}, err
	}
	totalLinks := 0
	allWarnings := []string{}
	switchesProcessed := 0
	for _, pr := range results {
		delta, err := p.persistInterfacesSwitch(pr, local, global)
		if err != nil {
			return PersistInterfacesStats{}, err
		}
		totalLinks += delta.linksInserted
		allWarnings = append(allWarnings, delta.warnings...)
		if delta.switchProcessed {
			switchesProcessed++
		}
	}
	return PersistInterfacesStats{
		Skipped:           false,
		SwitchesProcessed: switchesProcessed,
		VLANLinks:         totalLinks,
		PrepareErrors:     summarizeMessages(allWarnings),
	}, nil
}

func (p *Service) persistInterfacesSwitch(
	pr snmp.PollResult,
	local map[string]map[int]int,
	global map[int]int,
) (interfacesPersistDelta, error) {
	if !pr.Success {
		return interfacesPersistDelta{}, nil
	}
	sid := pr.Switch.ID
	if sid <= 0 {
		return interfacesPersistDelta{}, nil
	}
	// Обновляем sysname_snmp из sysDescr, если разрешено запросом update_switch_sysname_snmp.
	if p.repo.Company.IsPersistQueryEnabled("update_switch_sysname_snmp") {
		if err := p.repo.UpdateSwitchSysnameSNMP(sid, pr.SysDescr); err != nil {
			return interfacesPersistDelta{}, err
		}
	}
	if pr.Interfaces == nil {
		return interfacesPersistDelta{switchProcessed: true}, nil
	}
	n, warns, err := p.fillTablesFromInterfaces(sid, pr.Interfaces, pr.Switch.DomainID, pr.IP, local, global)
	if err != nil {
		return interfacesPersistDelta{}, err
	}
	return interfacesPersistDelta{
		linksInserted:   n,
		switchProcessed: true,
		warnings:        warns,
	}, nil
}

// PersistMAC выполняет upsert_mac_forward по строкам entries (формат MacTableFormatFDB), затем помечает устаревшие записи по границе времени
// (глобально или по VLAN — см. meta.obsolete_by_vlan в payload). dryRun прогоняет валидацию без записей; при Readonly без dryRun — skipped.
func (p *Service) PersistMAC(results []snmp.PollResult, dryRun bool) (PersistMACStats, error) {
	if p.repo.Readonly && !dryRun {
		return PersistMACStats{Skipped: true, PrepareErrors: []string{}}, nil
	}
	if len(results) == 0 {
		return PersistMACStats{PrepareErrors: []string{}}, nil
	}
	if !dryRun {
		if _, ok := p.repo.Company.Queries["upsert_mac_forward"]; !ok {
			return PersistMACStats{Skipped: true, PrepareErrors: []string{"upsert_mac_forward query not defined"}}, nil
		}
	}
	local, global, err := p.buildVLANMaps()
	if err != nil {
		return PersistMACStats{}, err
	}
	stats := PersistMACStats{}
	prepareErrors := []string{}
	for _, pr := range results {
		delta, err := p.persistMACSwitch(pr, dryRun, local, global)
		if err != nil {
			return PersistMACStats{}, err
		}
		prepareErrors = append(prepareErrors, delta.warnings...)
		stats.RowsUpserted += delta.rowsUpserted
		stats.MySQLAffectedRows += delta.mysqlAffectedRows
		stats.ObsoleteRowsAffected += delta.obsoleteRowsAffected
		if delta.switchProcessed {
			stats.SwitchesProcessed++
		}
	}
	stats.Skipped = false
	stats.PrepareErrors = summarizeMessages(prepareErrors)
	return stats, nil
}

func (p *Service) persistARPSwitch(
	pr snmp.PollResult,
	local map[string]map[int]int,
	global map[int]int,
	vrfMap map[string]int,
) (int, int64, []string, error) {
	if !pr.Success || len(pr.ArpTable.Entries) == 0 {
		return 0, 0, nil, nil
	}
	sid := pr.Switch.ID
	if sid <= 0 {
		return 0, 0, []string{fmt.Sprintf("ARP: некорректный switch_id в результате опроса (SwitchID=%v)", pr.SwitchID)}, nil
	}

	hostCtx := fmt.Sprintf("switch_id=%d, ip=%s", sid, pr.IP)
	domainID := pr.Switch.DomainID
	rowsUp := 0
	mysqlAffected := int64(0)
	warnings := []string{}

	for vlanKey, ips := range pr.ArpTable.Entries {
		vlanNum, vrfID, ok, warn := resolveARPVLANContext(vlanKey, vrfMap, hostCtx)
		if !ok {
			warnings = append(warnings, warn)
			continue
		}
		vdb, ok := resolveVLANID(vlanNum, domainID, local, global)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("%s, vlan=%d, domain_id=%v: VLAN не найден в справочнике БД (resolveVLANID)", hostCtx, vlanNum, domainID))
			continue
		}
		for ip, mac := range ips {
			macInt, err := normalizeMACToInt(mac)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s, dst_ip=%s: MAC %q: %v", hostCtx, ip, mac, err))
				continue
			}
			aff, err := p.repo.UpdateARPTable(vrfID, ip, macInt, vdb, sid)
			if err != nil {
				return 0, 0, nil, err
			}
			rowsUp++
			mysqlAffected += aff
		}
	}
	return rowsUp, mysqlAffected, warnings, nil
}

func resolveARPVLANContext(vlanKey string, vrfMap map[string]int, hostCtx string) (int, int, bool, string) {
	vlanNum, vrfName, ok := splitVLANVRF(vlanKey)
	if !ok {
		return 0, 0, false, fmt.Sprintf("%s: ключ VLAN в таблице ARP %q не разобран", hostCtx, vlanKey)
	}
	if vrfName == "" {
		return vlanNum, 0, true, ""
	}
	vrfID, ok := vrfMap[vrfName]
	if !ok {
		return 0, 0, false, fmt.Sprintf("%s, vlan=%d: VRF %q не найден в справочнике", hostCtx, vlanNum, vrfName)
	}
	return vlanNum, vrfID, true, ""
}

func (p *Service) persistMACSwitch(
	pr snmp.PollResult,
	dryRun bool,
	local map[string]map[int]int,
	global map[int]int,
) (macPersistDelta, error) {
	if !pr.Success || (pr.MacTable.Format == "" && len(pr.MacTable.Entries) == 0) {
		return macPersistDelta{}, nil
	}
	sid := pr.Switch.ID
	if sid <= 0 {
		return macPersistDelta{warnings: []string{fmt.Sprintf("invalid switch id in MAC row: %v", pr.SwitchID)}}, nil
	}
	hostCtx := fmt.Sprintf("switch_id=%d, ip=%s", sid, pr.IP)
	mt := pr.MacTable
	warnings := []string{}
	if fallbackMsg := buildFallbackCountersWarning(hostCtx, mt.Meta.FallbackVLANIfIndexCounts); fallbackMsg != "" {
		warnings = append(warnings, fallbackMsg)
	}
	if len(mt.Entries) == 0 {
		warnings = append(warnings, hostCtx+": поле entries пусто (формат "+snmp.MacTableFormatFDB+")")
		return macPersistDelta{warnings: warnings}, nil
	}
	prepared, rowWarnings := p.prepareMACRows(hostCtx, pr, local, global)
	warnings = append(warnings, rowWarnings...)
	if len(prepared) == 0 {
		return macPersistDelta{warnings: warnings}, nil
	}
	if !p.repo.Company.IsPersistQueryEnabled("upsert_mac_forward") {
		warnings = append(warnings, hostCtx+": upsert_mac_forward disabled, skipped")
		return macPersistDelta{warnings: warnings}, nil
	}
	if dryRun {
		return macPersistDelta{
			rowsUpserted:    len(prepared),
			switchProcessed: true,
			warnings:        warnings,
		}, nil
	}
	// Помечаем устаревшие MAC: границу берём до upsert’ов, чтобы «пропавшие» в этом опросе строки получили present=0.
	boundary, err := p.getSNMPPollBoundaryBefore()
	if err != nil {
		warnings = append(warnings, hostCtx+": boundary query failed: "+err.Error())
		return macPersistDelta{warnings: warnings}, nil
	}
	mysqlAffected, upserts, err := p.upsertPreparedMACRows(prepared)
	if err != nil {
		return macPersistDelta{}, err
	}
	portIDs := p.collectPortIDsBySwitch(sid)
	if len(portIDs) == 0 {
		warnings = append(warnings, hostCtx+": нет port_id для пометки устаревших (get_ifindex_to_port_id)")
		return macPersistDelta{
			rowsUpserted:      upserts,
			mysqlAffectedRows: mysqlAffected,
			warnings:          warnings,
		}, nil
	}
	aff, warn, err := p.markObsoleteForMACRows(boundary, prepared, portIDs, mt.Meta.ObsoleteByVLAN, hostCtx)
	if err != nil {
		return macPersistDelta{}, err
	}
	if warn != "" {
		warnings = append(warnings, warn)
	}
	return macPersistDelta{
		rowsUpserted:         upserts,
		mysqlAffectedRows:    mysqlAffected,
		obsoleteRowsAffected: aff,
		switchProcessed:      true,
		warnings:             warnings,
	}, nil
}

func (p *Service) upsertPreparedMACRows(prepared []macPreparedRow) (int64, int, error) {
	mysqlAffected := int64(0)
	upserts := 0
	for _, row := range prepared {
		aff, err := p.repo.UpsertMACForward(row.portID, row.vlanID, row.macInt, row.sta)
		if err != nil {
			return 0, 0, err
		}
		mysqlAffected += aff
		upserts++
	}
	return mysqlAffected, upserts, nil
}

func (p *Service) collectPortIDsBySwitch(switchID int) []int {
	ctx, _ := p.repo.BuildMACDBContext(switchID)
	portIDs := make([]int, 0, len(ctx.IfIndexToPortID))
	for _, pid := range ctx.IfIndexToPortID {
		portIDs = append(portIDs, pid)
	}
	return portIDs
}
