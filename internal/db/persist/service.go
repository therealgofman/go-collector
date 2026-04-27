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
	Repo *db.Repository
}

// New создаёт сервис записи для переданного репозитория.
func New(repo *db.Repository) *Service { return &Service{Repo: repo} }

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
	rows, err := p.Repo.GetVLANRows()
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
	rows, err := p.Repo.GetVRFRows()
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
	id, ok, err := p.Repo.GetPortIDByIfIndex(switchID, ifidx)
	if err != nil {
		return 0, false
	}
	return id, ok
}

// getPortByName ищет port_id по name.
func (p *Service) getPortByName(switchID int, name string) (int, bool) {
	id, ok, err := p.Repo.GetPortIDByName(switchID, name)
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
		pid, ok := p.getPortByIfIndex(switchID, row.ifIndex)
		if !ok {
			pid, ok = p.getPortByName(switchID, row.name)
		}
		if ok {
			if p.Repo.Company.IsPersistQueryEnabled("update_port") {
				if err := p.Repo.UpdatePort(pid, row.name, row.trunk, row.description, row.disabled, row.ifIndex, row.extraFields); err != nil {
					return count, warnings, err
				}
			}
		} else {
			// Если порт не найден, пытаемся создать его, если разрешено запросом insert_port.
			if !p.Repo.Company.IsPersistQueryEnabled("insert_port") {
				warnings = append(warnings, fmt.Sprintf("%s: port %s: insert_port disabled in persist_disabled_queries, skipped", ip, row.name))
				continue
			}
			role := "2"
			if row.trunk == 1 {
				role = "1"
			}
			inserted, err := p.Repo.InsertPort(switchID, row.trunk, row.name, row.description, row.ifIndex, role, row.extraFields)
			if err != nil {
				return count, warnings, err
			}
			pid = inserted
			if pid <= 0 {
				continue
			}
		}
		// Optional per-port persist hooks from collector/enricher.
		// Allows model-specific storage (e.g. port-security) via named YAML queries.
		for _, op := range row.persistOps {
			if op.query == "" {
				continue
			}
			if _, has := p.Repo.Company.Queries[op.query]; !has {
				warnings = append(warnings, fmt.Sprintf("%s: port %s: persist query %s not found, skipped", ip, row.name, op.query))
				continue
			}
			if !p.Repo.Company.IsPersistQueryEnabled(op.query) {
				warnings = append(warnings, fmt.Sprintf("%s: port %s: persist query %s disabled, skipped", ip, row.name, op.query))
				continue
			}
			if err := p.Repo.ExecPortPersistHook(
				op.query,
				switchID,
				pid,
				row.ifIndex,
				row.name,
				row.trunk,
				row.description,
				row.disabled,
				op.bind,
			); err != nil {
				return count, warnings, err
			}
		}
		// Синхронизация port2vlan: сначала удаляем старые связи, затем вставляем новые.
		canDelete := p.Repo.Company.IsPersistQueryEnabled("delete_port2vlan_by_port")
		canInsert := p.Repo.Company.IsPersistQueryEnabled("insert_port2vlan")
		if !canDelete && len(row.vlans) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: port %s: VLAN sync skipped (delete_port2vlan_by_port disabled)", ip, row.name))
		} else if canDelete {
			if err := p.Repo.DeletePort2VLANByPort(pid); err != nil {
				return count, warnings, err
			}
			if !canInsert && len(row.vlans) > 0 {
				warnings = append(warnings, fmt.Sprintf("%s: port %s: insert_port2vlan disabled, VLAN links removed", ip, row.name))
			}
			if canInsert {
				for _, vlanNum := range row.vlans {
					vid, ok := resolveVLANID(vlanNum, domainID, local, global)
					if !ok {
						warnings = append(warnings, fmt.Sprintf("%s\tunknown vlan %d on port %s", ip, vlanNum, row.name))
						continue
					}
					if err := p.Repo.InsertPort2VLAN(pid, vid); err != nil {
						return count, warnings, err
					}
					count++
				}
			}
		}
	}
	return count, warnings, nil
}

// getSNMPPollBoundaryBefore читает метку времени «чуть раньше сейчас» — границу для пометки устаревших MAC (не попавших в текущий опрос).
func (p *Service) getSNMPPollBoundaryBefore() (int, error) {
	return p.Repo.GetSNMPTimestampBoundaryBefore()
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
		return p.Repo.MarkMACObsoleteGlobal(boundary, portIDsIn)
	}
	return p.Repo.MarkMACObsoleteByVLAN(boundary, *vlanID, portIDsIn)
}

// PersistARP записывает ARP: для каждого успешного результата разбирает VLAN/VRF, резолвит vlan_id, upsert в ip_arp.
// Ошибки подготовки отдельных строк попадают в prepare_errors; фатальные ошибки БД прерывают весь вызов.
func (p *Service) PersistARP(results []snmp.PollResult) (PersistARPStats, error) {
	if p.Repo.Readonly {
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
	rowsUp := 0
	mysqlAffected := int64(0)
	prepareErrors := []string{}
	for _, pr := range results {
		if !pr.Success || len(pr.ArpTable.Entries) == 0 {
			continue
		}
		sid := pr.Switch.ID
		if sid <= 0 {
			prepareErrors = append(prepareErrors, fmt.Sprintf("ARP: некорректный switch_id в результате опроса (SwitchID=%v)", pr.SwitchID))
			continue
		}
		hostCtx := fmt.Sprintf("switch_id=%d, ip=%s", sid, pr.IP)
		domainID := pr.Switch.DomainID
		for vlanKey, ips := range pr.ArpTable.Entries {
			vlanNum, vrfName, ok := splitVLANVRF(vlanKey)
			if !ok {
				prepareErrors = append(prepareErrors, fmt.Sprintf("%s: ключ VLAN в таблице ARP %q не разобран", hostCtx, vlanKey))
				continue
			}
			vrfID := 0
			if vrfName != "" {
				v, ok := vrfMap[vrfName]
				if !ok {
					prepareErrors = append(prepareErrors, fmt.Sprintf("%s, vlan=%d: VRF %q не найден в справочнике", hostCtx, vlanNum, vrfName))
					continue
				}
				vrfID = v
			}
			vdb, ok := resolveVLANID(vlanNum, domainID, local, global)
			if !ok {
				prepareErrors = append(prepareErrors, fmt.Sprintf("%s, vlan=%d, domain_id=%v: VLAN не найден в справочнике БД (resolveVLANID)", hostCtx, vlanNum, domainID))
				continue
			}
			for ip, mac := range ips {
				macInt, err := normalizeMACToInt(mac)
				if err != nil {
					prepareErrors = append(prepareErrors, fmt.Sprintf("%s, dst_ip=%s: MAC %q: %v", hostCtx, ip, mac, err))
					continue
				}
				aff, err := p.Repo.UpdateARPTable(vrfID, ip, macInt, vdb, sid)
				if err != nil {
					return PersistARPStats{}, err
				}
				rowsUp++
				mysqlAffected += aff
			}
		}
	}
	return PersistARPStats{
		Skipped:           false,
		RowsUpserted:      rowsUp,
		MySQLAffectedRows: mysqlAffected,
		SwitchesProcessed: len(results),
		PrepareErrors:     summarizeMessages(prepareErrors),
	}, nil
}

// PersistInterfaces обновляет sysname_snmp (если разрешено), для каждого свитча вызывает fillTablesFromInterfaces.
func (p *Service) PersistInterfaces(results []snmp.PollResult) (PersistInterfacesStats, error) {
	if p.Repo.Readonly {
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
		if !pr.Success {
			continue
		}
		sid := pr.Switch.ID
		if sid <= 0 {
			continue
		}
		// Обновляем sysname_snmp из sysDescr, если разрешено запросом update_switch_sysname_snmp.
		if p.Repo.Company.IsPersistQueryEnabled("update_switch_sysname_snmp") {
			if err := p.Repo.UpdateSwitchSysnameSNMP(sid, pr.SysDescr); err != nil {
				return PersistInterfacesStats{}, err
			}
		}
		if pr.Interfaces != nil {
			n, warns, err := p.fillTablesFromInterfaces(sid, pr.Interfaces, pr.Switch.DomainID, pr.IP, local, global)
			if err != nil {
				return PersistInterfacesStats{}, err
			}
			totalLinks += n
			allWarnings = append(allWarnings, warns...)
		}
		switchesProcessed++
	}
	return PersistInterfacesStats{
		Skipped:           false,
		SwitchesProcessed: switchesProcessed,
		VLANLinks:         totalLinks,
		PrepareErrors:     summarizeMessages(allWarnings),
	}, nil
}

// PersistMAC выполняет upsert_mac_forward по строкам entries (формат MacTableFormatFDB), затем помечает устаревшие записи по границе времени
// (глобально или по VLAN — см. meta.obsolete_by_vlan в payload). dryRun прогоняет валидацию без записей; при Readonly без dryRun — skipped.
func (p *Service) PersistMAC(results []snmp.PollResult, dryRun bool) (PersistMACStats, error) {
	if p.Repo.Readonly && !dryRun {
		return PersistMACStats{Skipped: true, PrepareErrors: []string{}}, nil
	}
	if len(results) == 0 {
		return PersistMACStats{PrepareErrors: []string{}}, nil
	}
	if !dryRun {
		if _, ok := p.Repo.Company.Queries["upsert_mac_forward"]; !ok {
			return PersistMACStats{Skipped: true, PrepareErrors: []string{"upsert_mac_forward query not defined"}}, nil
		}
	}
	local, global, err := p.buildVLANMaps()
	if err != nil {
		return PersistMACStats{}, err
	}
	total := 0
	mysqlSum := int64(0)
	obsoleteRowsAffected := int64(0)
	prepareErrors := []string{}
	switchesProcessed := 0
	for _, pr := range results {
		if !pr.Success || (pr.MacTable.Format == "" && len(pr.MacTable.Entries) == 0) {
			continue
		}
		sid := pr.Switch.ID
		if sid <= 0 {
			prepareErrors = append(prepareErrors, fmt.Sprintf("invalid switch id in MAC row: %v", pr.SwitchID))
			continue
		}
		hostCtx := fmt.Sprintf("switch_id=%d, ip=%s", sid, pr.IP)
		mt := pr.MacTable
		if fallback := mt.Meta.FallbackVLANIfIndexCounts; len(fallback) > 0 {
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
			prepareErrors = append(prepareErrors, msg)
		}
		if len(mt.Entries) == 0 {
			prepareErrors = append(prepareErrors, hostCtx+": поле entries пусто (формат "+snmp.MacTableFormatFDB+")")
			continue
		}
		type preparedRow struct {
			portID, vlanID int
			macInt         uint64
			sta            int
		}
		prepared := []preparedRow{}
		for _, row := range mt.Entries {
			pid := row.PortID
			if pid <= 0 {
				prepareErrors = append(prepareErrors, fmt.Sprintf("%s: no port_id (skip)", hostCtx))
				continue
			}
			vid := row.VLANID
			if vid <= 0 {
				vnum := row.VLAN
				if vnum <= 0 {
					prepareErrors = append(prepareErrors, fmt.Sprintf("%s: no vlan_id/vlan", hostCtx))
					continue
				}
				if resolved, ok := resolveVLANID(vnum, pr.Switch.DomainID, local, global); ok {
					vid = resolved
				} else {
					if vnum == 9999 {
						// Для fallback-9999 не дублируем построчными prepare_errors:
						// агрегат выводится из typed meta.FallbackVLANIfIndexCounts.
						continue
					}
					prepareErrors = append(prepareErrors, fmt.Sprintf("%s, vlan=%d, domain_id=%s: VLAN не найден в справочнике БД (resolveVLANID)", hostCtx, vnum, pr.Switch.DomainID))
					continue
				}
			}
			macInt, err := normalizeMACToInt(row.MAC)
			if err != nil {
				prepareErrors = append(prepareErrors, fmt.Sprintf("%s: mac %q: %v", hostCtx, row.MAC, err))
				continue
			}
			prepared = append(prepared, preparedRow{portID: pid, vlanID: vid, macInt: macInt, sta: row.Status})
		}
		if len(prepared) == 0 {
			continue
		}
		if !p.Repo.Company.IsPersistQueryEnabled("upsert_mac_forward") {
			prepareErrors = append(prepareErrors, hostCtx+": upsert_mac_forward disabled, skipped")
			continue
		}
		if dryRun {
			total += len(prepared)
			switchesProcessed++
			continue
		}
		// Помечаем устаревшие MAC: границу берём до upsert’ов, чтобы «пропавшие» в этом опросе строки получили present=0.
		boundary, err := p.getSNMPPollBoundaryBefore()
		if err != nil {
			prepareErrors = append(prepareErrors, hostCtx+": boundary query failed: "+err.Error())
			continue
		}
		for _, row := range prepared {
			aff, err := p.Repo.UpsertMACForward(row.portID, row.vlanID, row.macInt, row.sta)
			if err != nil {
				return PersistMACStats{}, err
			}
			mysqlSum += aff
			total++
		}
		ctx, _ := p.Repo.BuildMACDBContext(sid)
		portIDs := make([]int, 0, len(ctx.IfIndexToPortID))
		for _, pid := range ctx.IfIndexToPortID {
			portIDs = append(portIDs, pid)
		}
		if len(portIDs) == 0 {
			prepareErrors = append(prepareErrors, hostCtx+": нет port_id для пометки устаревших (get_ifindex_to_port_id)")
			continue
		}
		byVlan := mt.Meta.ObsoleteByVLAN
		canGlobal := p.Repo.Company.IsPersistQueryEnabled("mark_mac_obsolete_global")
		canBy := p.Repo.Company.IsPersistQueryEnabled("mark_mac_obsolete_by_vlan")
		if byVlan {
			if canBy {
				seen := map[int]struct{}{}
				for _, row := range prepared {
					if _, ok := seen[row.vlanID]; ok {
						continue
					}
					seen[row.vlanID] = struct{}{}
					v := row.vlanID
					aff, err := p.markObsoleteMAC(boundary, portIDs, &v)
					if err != nil {
						return PersistMACStats{}, err
					}
					obsoleteRowsAffected += aff
				}
			} else {
				prepareErrors = append(prepareErrors, hostCtx+": режим пометки по VLAN (obsolete_by_vlan), но запрос mark_mac_obsolete_by_vlan отключён — пометка устаревших пропущена")
			}
		} else if canGlobal {
			aff, err := p.markObsoleteMAC(boundary, portIDs, nil)
			if err != nil {
				return PersistMACStats{}, err
			}
			obsoleteRowsAffected += aff
		} else {
			prepareErrors = append(prepareErrors, hostCtx+": запросы пометки устаревших отключены (persist_disabled_queries)")
		}
		switchesProcessed++
	}
	return PersistMACStats{
		Skipped:              false,
		RowsUpserted:         total,
		MySQLAffectedRows:    mysqlSum,
		PrepareErrors:        summarizeMessages(prepareErrors),
		ObsoleteRowsAffected: obsoleteRowsAffected,
		SwitchesProcessed:    switchesProcessed,
	}, nil
}
