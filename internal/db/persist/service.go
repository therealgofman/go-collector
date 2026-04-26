// Package persist записывает результаты SNMP в MySQL: интерфейсы/VLAN, ARP, MAC.
package persist

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go-collector/internal/db"
	"go-collector/internal/helpers"
	"go-collector/internal/snmp"
)

// Service инкапсулирует сценарии сохранения поверх db.Repository (без дублирования SQL в вызывающем коде).
type Service struct {
	Repo *db.Repository
}

// New создаёт сервис записи для переданного репозитория.
func New(repo *db.Repository) *Service { return &Service{Repo: repo} }

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
	rows, err := p.Repo.QueryRows("get_vlans", nil)
	if err != nil {
		return nil, nil, err
	}
	local := map[string]map[int]int{}
	global := map[int]int{}
	for _, row := range rows {
		vid, ok := helpers.FirstExistingInt(row, "d_vlan_id", "vlan_id")
		if !ok {
			continue
		}
		vnum, ok := helpers.AsInt(row["number"])
		if !ok {
			continue
		}
		domKey := helpers.AsString(row["domain_id"])
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
func resolveVLANID(vlan int, domain any, local map[string]map[int]int, global map[int]int) (int, bool) {
	dk := helpers.AsString(domain)
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
	rows, err := p.Repo.QueryRows("get_vrf_map", nil)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, row := range rows {
		id, ok := helpers.AsInt(row["id"])
		if !ok {
			continue
		}
		name := helpers.AsString(row["name"])
		if name != "" {
			out[name] = id
		}
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
	extraFields map[string]any
	persistOps  []parsedPortPersistOp
}

type parsedPortPersistOp struct {
	query string
	bind  map[string]any
}

func asStringAnyMap(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

// parsePortPersistOps поддерживает 2 формы:
// 1) persist: [{query: "upsert_port_security", params: {...}}, ...]
// 2) persist: {upsert_port_security: {...}, another_query: {...}}
func parsePortPersistOps(pdata map[string]any) []parsedPortPersistOp {
	raw, ok := pdata["persist"]
	if !ok || raw == nil {
		return nil
	}
	out := []parsedPortPersistOp{}
	if arr, ok := raw.([]any); ok {
		for _, it := range arr {
			item, ok := it.(map[string]any)
			if !ok {
				continue
			}
			q := strings.TrimSpace(helpers.AsString(item["query"]))
			if q == "" {
				continue
			}
			params := asStringAnyMap(item["params"])
			if params == nil {
				params = map[string]any{}
			}
			out = append(out, parsedPortPersistOp{query: q, bind: params})
		}
		return out
	}
	if m, ok := raw.(map[string]any); ok {
		for q, v := range m {
			q = strings.TrimSpace(q)
			if q == "" {
				continue
			}
			params := asStringAnyMap(v)
			if params == nil {
				params = map[string]any{}
			}
			out = append(out, parsedPortPersistOp{query: q, bind: params})
		}
	}
	return out
}

// parseInterfaces превращает map[string]any из CollectInterfaces в срез с отсортированным списком VLAN на порт.
func parseInterfaces(interfaces map[string]any) []parsedInterface {
	out := []parsedInterface{}
	baseKeys := map[string]struct{}{
		"ifindex": {}, "name": {}, "tag": {}, "descr": {}, "disab": {}, "vlan": {}, "persist": {},
	}
	for pkey, pdataRaw := range interfaces {
		pdata, ok := pdataRaw.(map[string]any)
		if !ok {
			continue
		}
		ifidx := 0
		if v, ok := helpers.AsInt(pdata["ifindex"]); ok {
			ifidx = v
		} else if v, err := strconv.Atoi(strings.TrimSpace(pkey)); err == nil {
			ifidx = v
		}
		trunk := 0
		if tv, ok := pdata["tag"]; ok && helpers.AsString(tv) != "" && helpers.AsString(tv) != "0" {
			trunk = 1
		}
		dis := 0
		if dv, ok := helpers.AsInt(pdata["disab"]); ok && dv != 0 {
			dis = 1
		}
		name := helpers.AsString(pdata["name"])
		if name == "" {
			name = pkey
		}
		descr := helpers.AsString(pdata["descr"])
		vlans := []int{}
		// Поддерживаются оба представления vlan: map[string]any и map[int]int —
		// разные ветки моделей могут отдавать тот или другой формат.
		if vraw, ok := pdata["vlan"].(map[string]any); ok {
			for k := range vraw {
				if strings.TrimSpace(k) == "none" {
					continue
				}
				if n, err := strconv.Atoi(strings.TrimSpace(k)); err == nil {
					vlans = append(vlans, n)
				}
			}
		} else if vraw, ok := pdata["vlan"].(map[int]int); ok {
			for k := range vraw {
				vlans = append(vlans, k)
			}
		}
		sort.Ints(vlans)
		extra := map[string]any{}
		for k, v := range pdata {
			if _, ok := baseKeys[k]; ok {
				continue
			}
			extra[k] = v
		}

		out = append(out, parsedInterface{
			ifIndex: ifidx, name: name, trunk: trunk, description: descr, disabled: dis, vlans: vlans, extraFields: extra, persistOps: parsePortPersistOps(pdata),
		})
	}
	return out
}

// getPortByIfIndex ищет port_id по ifindex.
func (p *Service) getPortByIfIndex(switchID int, ifidx int) (int, bool) {
	rows, err := p.Repo.QueryRows("get_port_by_ifindex", map[string]any{"switch_id": switchID, "ifindex": ifidx})
	if err != nil || len(rows) == 0 {
		return 0, false
	}
	for _, v := range rows[0] {
		n, ok := helpers.AsInt(v)
		return n, ok
	}
	return 0, false
}

// getPortByName ищет port_id по name.
func (p *Service) getPortByName(switchID int, name string) (int, bool) {
	rows, err := p.Repo.QueryRows("get_port_by_name", map[string]any{"switch_id": switchID, "name": name})
	if err != nil || len(rows) == 0 {
		return 0, false
	}
	for _, v := range rows[0] {
		n, ok := helpers.AsInt(v)
		return n, ok
	}
	return 0, false
}

// fillTablesFromInterfaces обновляет или создаёт порты, синхронизирует port2vlan (delete + insert),
// возвращает число вставленных связей VLAN и предупреждения о неизвестных VLAN.
func (p *Service) fillTablesFromInterfaces(switchID int, interfaces map[string]any, domainID any, ip string, local map[string]map[int]int, global map[int]int) (int, []string, error) {
	count := 0
	warnings := []string{}
	for _, row := range parseInterfaces(interfaces) {
		pid, ok := p.getPortByIfIndex(switchID, row.ifIndex)
		if !ok {
			pid, ok = p.getPortByName(switchID, row.name)
		}
		if ok {
			if p.Repo.Company.IsPersistQueryEnabled("update_port") {
				bind := map[string]any{
					"port_id":     pid,
					"name":        row.name,
					"trunk":       row.trunk,
					"description": row.description,
					"disabled":    row.disabled,
					"ifindex":     row.ifIndex,
				}
				for k, v := range row.extraFields {
					if _, exists := bind[k]; exists {
						continue
					}
					bind[k] = v
				}
				if _, err := p.Repo.Exec("update_port", bind, nil); err != nil {
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
			bind := map[string]any{
				"switch_id":   switchID,
				"trunk":       row.trunk,
				"name":        row.name,
				"description": row.description,
				"ifindex":     row.ifIndex,
				"role":        role,
			}
			for k, v := range row.extraFields {
				if _, exists := bind[k]; exists {
					continue
				}
				bind[k] = v
			}
			last, err := p.Repo.ExecInsertLastID("insert_port", bind, nil)
			if err != nil {
				return count, warnings, err
			}
			pid = int(last)
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
			bind := map[string]any{
				"switch_id":   switchID,
				"port_id":     pid,
				"ifindex":     row.ifIndex,
				"name":        row.name,
				"trunk":       row.trunk,
				"description": row.description,
				"disabled":    row.disabled,
			}
			for k, v := range op.bind {
				bind[k] = v
			}
			if _, err := p.Repo.Exec(op.query, bind, nil); err != nil {
				return count, warnings, err
			}
		}
		// Синхронизация port2vlan: сначала удаляем старые связи, затем вставляем новые.
		canDelete := p.Repo.Company.IsPersistQueryEnabled("delete_port2vlan_by_port")
		canInsert := p.Repo.Company.IsPersistQueryEnabled("insert_port2vlan")
		if !canDelete && len(row.vlans) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: port %s: VLAN sync skipped (delete_port2vlan_by_port disabled)", ip, row.name))
		} else if canDelete {
			if _, err := p.Repo.Exec("delete_port2vlan_by_port", map[string]any{"port_id": pid}, nil); err != nil {
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
					if _, err := p.Repo.Exec("insert_port2vlan", map[string]any{"port_id": pid, "vlan_id": vid}, nil); err != nil {
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
	rows, err := p.Repo.QueryRows("get_snmp_timestamp_boundary", nil)
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
	extra := map[string]any{"port_ids_in": strings.Join(parts, ",")}
	params := map[string]any{"boundary_before": boundary}
	if vlanID == nil {
		return p.Repo.Exec("mark_mac_obsolete_global", params, extra)
	}
	params["vlan_id"] = *vlanID
	return p.Repo.Exec("mark_mac_obsolete_by_vlan", params, extra)
}

// PersistARP записывает ARP: для каждого успешного результата разбирает VLAN/VRF, резолвит vlan_id, upsert в ip_arp.
// Ошибки подготовки отдельных строк попадают в prepare_errors; фатальные ошибки БД прерывают весь вызов.
func (p *Service) PersistARP(results []snmp.PollResult) (map[string]any, error) {
	if p.Repo.Readonly {
		return map[string]any{"skipped": true, "rows_upserted": 0, "mysql_affected_rows_sum": 0, "prepare_errors": []string{}, "switches_processed": 0}, nil
	}
	if len(results) == 0 {
		return map[string]any{"skipped": false, "rows_upserted": 0, "mysql_affected_rows_sum": 0, "prepare_errors": []string{}, "switches_processed": 0}, nil
	}
	local, global, err := p.buildVLANMaps()
	if err != nil {
		return nil, err
	}
	vrfMap, err := p.getVRFNameToID()
	if err != nil {
		return nil, err
	}
	rowsUp := 0
	mysqlAffected := int64(0)
	prepareErrors := []string{}
	for _, pr := range results {
		if !pr.Success || pr.ArpTable == nil {
			continue
		}
		sid, _ := helpers.FirstExistingInt(pr.RawSwitch, "d_switch_id", "switch_id")
		if sid <= 0 {
			prepareErrors = append(prepareErrors, fmt.Sprintf("ARP: некорректный switch_id в результате опроса (SwitchID=%v)", pr.SwitchID))
			continue
		}
		hostCtx := fmt.Sprintf("switch_id=%d, ip=%s", sid, pr.IP)
		domainID := pr.RawSwitch["domain_id"]
		for vlanKey, ips := range pr.ArpTable {
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
				aff, err := p.Repo.Exec("update_arp_table", map[string]any{
					"vrf_id": vrfID, "ip": ip, "mac": macInt, "vlan_id": vdb, "switch_id": sid,
				}, nil)
				if err != nil {
					return nil, err
				}
				rowsUp++
				mysqlAffected += aff
			}
		}
	}
	return map[string]any{
		"skipped": false, "rows_upserted": rowsUp, "mysql_affected_rows_sum": mysqlAffected,
		"switches_processed": len(results), "prepare_errors": summarizeMessages(prepareErrors),
	}, nil
}

// PersistInterfaces обновляет sysname_snmp (если разрешено), для каждого свитча вызывает fillTablesFromInterfaces.
func (p *Service) PersistInterfaces(results []snmp.PollResult) (map[string]any, error) {
	if p.Repo.Readonly {
		return map[string]any{"skipped": true, "switches_processed": 0, "vlan_links": 0, "prepare_errors": []string{}}, nil
	}
	if len(results) == 0 {
		return map[string]any{"skipped": false, "switches_processed": 0, "vlan_links": 0, "prepare_errors": []string{}}, nil
	}
	local, global, err := p.buildVLANMaps()
	if err != nil {
		return nil, err
	}
	totalLinks := 0
	allWarnings := []string{}
	switchesProcessed := 0
	for _, pr := range results {
		if !pr.Success {
			continue
		}
		sid, _ := helpers.FirstExistingInt(pr.RawSwitch, "d_switch_id", "switch_id")
		if sid <= 0 {
			continue
		}
		// Обновляем sysname_snmp из sysDescr, если разрешено запросом update_switch_sysname_snmp.
		if p.Repo.Company.IsPersistQueryEnabled("update_switch_sysname_snmp") {
			if _, err := p.Repo.Exec("update_switch_sysname_snmp", map[string]any{"switch_id": sid, "sysname_snmp": pr.SysDescr}, nil); err != nil {
				return nil, err
			}
		}
		if pr.Interfaces != nil {
			n, warns, err := p.fillTablesFromInterfaces(sid, pr.Interfaces, pr.RawSwitch["domain_id"], pr.IP, local, global)
			if err != nil {
				return nil, err
			}
			totalLinks += n
			allWarnings = append(allWarnings, warns...)
		}
		switchesProcessed++
	}
	return map[string]any{
		"skipped": false, "switches_processed": switchesProcessed, "vlan_links": totalLinks, "prepare_errors": summarizeMessages(allWarnings),
	}, nil
}

// PersistMAC выполняет upsert_mac_forward по строкам entries (формат MacTableFormatFDB), затем помечает устаревшие записи по границе времени
// (глобально или по VLAN — см. meta.obsolete_by_vlan в payload). dryRun прогоняет валидацию без записей; при Readonly без dryRun — skipped.
func (p *Service) PersistMAC(results []snmp.PollResult, dryRun bool) (map[string]any, error) {
	if p.Repo.Readonly && !dryRun {
		return map[string]any{"skipped": true, "rows_upserted": 0, "mysql_affected_rows_sum": 0, "prepare_errors": []string{}, "obsolete_rows_affected": 0, "switches_processed": 0}, nil
	}
	if len(results) == 0 {
		return map[string]any{"skipped": false, "rows_upserted": 0, "mysql_affected_rows_sum": 0, "prepare_errors": []string{}, "obsolete_rows_affected": 0, "switches_processed": 0}, nil
	}
	if !dryRun {
		if _, ok := p.Repo.Company.Queries["upsert_mac_forward"]; !ok {
			return map[string]any{"skipped": true, "rows_upserted": 0, "mysql_affected_rows_sum": 0, "prepare_errors": []string{"upsert_mac_forward query not defined"}, "obsolete_rows_affected": 0, "switches_processed": 0}, nil
		}
	}
	local, global, err := p.buildVLANMaps()
	if err != nil {
		return nil, err
	}
	total := 0
	mysqlSum := int64(0)
	obsoleteRowsAffected := int64(0)
	prepareErrors := []string{}
	switchesProcessed := 0
	for _, pr := range results {
		if !pr.Success || pr.MacTable == nil {
			continue
		}
		sid, _ := helpers.FirstExistingInt(pr.RawSwitch, "d_switch_id", "switch_id")
		if sid <= 0 {
			prepareErrors = append(prepareErrors, fmt.Sprintf("invalid switch id in MAC row: %v", pr.SwitchID))
			continue
		}
		hostCtx := fmt.Sprintf("switch_id=%d, ip=%s", sid, pr.IP)
		if meta, ok := pr.MacTable["meta"].(map[string]any); ok {
			if extra, ok := meta["extra"].(map[string]any); ok {
				fallback := helpers.ToNestedIntMap(extra["fallback_vlan_ifindex_counts"])
				if len(fallback) > 0 {
					vlans := make([]string, 0, len(fallback))
					for v := range fallback {
						vlans = append(vlans, v)
					}
					sort.Strings(vlans)
					msg := fmt.Sprintf("%s: fallback VLAN counters from collector", hostCtx)
					for _, v := range vlans {
						table := map[string]int{}
						for ifidx, n := range fallback[v] {
							table[fmt.Sprintf("ifindex=%s", ifidx)] = n
						}
						msg += renderTopTable("vlan="+v, table)
					}
					prepareErrors = append(prepareErrors, msg)
				}
			}
		}
		rawEntries, ok := pr.MacTable["entries"].([]any)
		if !ok {
			prepareErrors = append(prepareErrors, hostCtx+": поле entries должно быть списком (формат "+snmp.MacTableFormatFDB+")")
			continue
		}
		type preparedRow struct {
			portID, vlanID int
			macInt         uint64
			sta            int
		}
		prepared := []preparedRow{}
		for i, item := range rawEntries {
			row, ok := item.(map[string]any)
			if !ok {
				prepareErrors = append(prepareErrors, fmt.Sprintf("%s: list_index=%d: not a dict", hostCtx, i))
				continue
			}
			pid, ok := helpers.AsInt(row["port_id"])
			if !ok || pid <= 0 {
				prepareErrors = append(prepareErrors, fmt.Sprintf("%s: no port_id (skip)", hostCtx))
				continue
			}
			vid, ok := helpers.AsInt(row["vlan_id"])
			if !ok || vid <= 0 {
				vnum, ok := helpers.AsInt(row["vlan"])
				if !ok {
					prepareErrors = append(prepareErrors, fmt.Sprintf("%s: no vlan_id/vlan", hostCtx))
					continue
				}
				if resolved, ok := resolveVLANID(vnum, pr.RawSwitch["domain_id"], local, global); ok {
					vid = resolved
				} else {
					if vnum == 9999 {
						// Для fallback-9999 не дублируем построчными prepare_errors:
						// агрегат выводится из meta.extra (fallback_vlan_ifindex_counts).
						continue
					}
					prepareErrors = append(prepareErrors, fmt.Sprintf("%s, vlan=%d, domain_id=%v: VLAN не найден в справочнике БД (resolveVLANID)", hostCtx, vnum, pr.RawSwitch["domain_id"]))
					continue
				}
			}
			macInt, err := normalizeMACToInt(helpers.AsString(row["mac"]))
			if err != nil {
				prepareErrors = append(prepareErrors, fmt.Sprintf("%s: mac %q: %v", hostCtx, helpers.AsString(row["mac"]), err))
				continue
			}
			sta, _ := helpers.AsInt(row["status"])
			prepared = append(prepared, preparedRow{portID: pid, vlanID: vid, macInt: macInt, sta: sta})
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
			aff, err := p.Repo.Exec("upsert_mac_forward", map[string]any{
				"port_id": row.portID, "vlan_id": row.vlanID, "mac": row.macInt, "sta": row.sta,
			}, nil)
			if err != nil {
				return nil, err
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
		meta, _ := pr.MacTable["meta"].(map[string]any)
		byVlan := meta != nil && meta["obsolete_by_vlan"] == true
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
						return nil, err
					}
					obsoleteRowsAffected += aff
				}
			} else {
				prepareErrors = append(prepareErrors, hostCtx+": режим пометки по VLAN (obsolete_by_vlan), но запрос mark_mac_obsolete_by_vlan отключён — пометка устаревших пропущена")
			}
		} else if canGlobal {
			aff, err := p.markObsoleteMAC(boundary, portIDs, nil)
			if err != nil {
				return nil, err
			}
			obsoleteRowsAffected += aff
		} else {
			prepareErrors = append(prepareErrors, hostCtx+": запросы пометки устаревших отключены (persist_disabled_queries)")
		}
		switchesProcessed++
	}
	return map[string]any{
		"skipped": false, "rows_upserted": total, "mysql_affected_rows_sum": mysqlSum, "prepare_errors": summarizeMessages(prepareErrors),
		"obsolete_rows_affected": obsoleteRowsAffected, "switches_processed": switchesProcessed,
	}, nil
}
