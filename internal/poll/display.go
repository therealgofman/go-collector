// Package poll (display): форматирование результатов опроса в консоль.
package poll

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go-collector/internal/snmp"
)

// sortIfIndexKey возвращает ключ сортировки: числовые ifIndex сначала с дополнением нулями.
func sortIfIndexKey(idx string) (int, string) {
	if n, err := strconv.Atoi(idx); err == nil {
		return 0, fmt.Sprintf("%09d", n)
	}
	return 1, idx
}

// truncateField сжимает пробелы/переводы строк и обрезает строку для колонки таблицы.
func truncateField(s string, maxLen int) string {
	t := strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(t) <= maxLen {
		return t
	}
	if maxLen <= 1 {
		return t[:maxLen]
	}
	return t[:maxLen-1] + "..."
}

// formatVLANCompact форматирует map VLAN для одной строки вывода (до 10 номеров + счётчик остатка).
func formatVLANCompact(v any) string {
	m, ok := v.(map[int]int)
	if !ok || len(m) == 0 {
		if mm, ok := v.(map[string]any); ok && len(mm) > 0 {
			keys := make([]string, 0, len(mm))
			for k := range mm {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) <= 10 {
				return strings.Join(keys, ",")
			}
			return strings.Join(keys[:10], ",") + fmt.Sprintf("+%d", len(keys)-10)
		}
		return "-"
	}
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, strconv.Itoa(k))
	}
	if len(parts) <= 10 {
		return strings.Join(parts, ",")
	}
	return strings.Join(parts[:10], ",") + fmt.Sprintf("+%d", len(parts)-10)
}

// PrintSwitchInterfaces печатает таблицу портов: ifIndex, name, descr, disab, trunk tag, список VLAN.
func PrintSwitchInterfaces(result map[string]any, switchLabel string, ip string) {
	banner := "interfaces"
	if switchLabel != "" && ip != "" {
		banner = fmt.Sprintf("[%s] interfaces @ %s", switchLabel, ip)
	} else if switchLabel != "" {
		banner = fmt.Sprintf("[%s] interfaces", switchLabel)
	} else if ip != "" {
		banner = fmt.Sprintf("interfaces @ %s", ip)
	}
	if len(result) == 0 {
		fmt.Printf("\n%s: (empty)\n", banner)
		return
	}
	type row struct {
		ifidx, name, descr, dis, tg, vlans string
	}
	rows := make([]row, 0, len(result))
	for idx, raw := range result {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		ifidx := strings.TrimSpace(fmt.Sprint(p["ifindex"]))
		if ifidx == "" || ifidx == "<nil>" {
			ifidx = idx
		}
		dis := "-"
		if fmt.Sprint(p["disab"]) == "1" {
			dis = "D"
		}
		tg := "-"
		if fmt.Sprint(p["tag"]) == "1" {
			tg = "Y"
		}
		rows = append(rows, row{
			ifidx: ifidx,
			name:  fmt.Sprint(p["name"]),
			descr: fmt.Sprint(p["descr"]),
			dis:   dis,
			tg:    tg,
			vlans: formatVLANCompact(p["vlan"]),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		ai, as := sortIfIndexKey(rows[i].ifidx)
		bi, bs := sortIfIndexKey(rows[j].ifidx)
		if ai != bi {
			return ai < bi
		}
		return as < bs
	})
	wIf, wNm, wDs := 9, 22, 34
	fmt.Printf("\n%s (%d ports):\n", banner, len(rows))
	h := fmt.Sprintf("%-*s %-*s %-*s %3s %3s VLANs", wIf, "ifIndex", wNm, "name", wDs, "descr", "dis", "tg")
	fmt.Println(h)
	fmt.Println(strings.Repeat("-", min(120, len(h)+40)))
	for _, r := range rows {
		fmt.Printf("%-*s %-*s %-*s %3s %3s %s\n",
			wIf, r.ifidx,
			wNm, truncateField(r.name, wNm),
			wDs, truncateField(r.descr, wDs),
			r.dis, r.tg, r.vlans,
		)
	}
}

// PrintArpPollSummary выводит по каждому результату число ARP-записей и разбивку по VLAN.
func PrintArpPollSummary(results []snmp.PollResult) {
	for _, r := range results {
		label := fmt.Sprint(r.SwitchID)
		if !r.Success {
			err := r.Error
			if err == "" {
				err = "unknown"
			}
			fmt.Printf("\n[%s] ARP @ %s: failed - %s\n", label, r.IP, err)
			continue
		}
		if len(r.ArpTable) == 0 {
			fmt.Printf("\n[%s] ARP @ %s: (empty)\n", label, r.IP)
			continue
		}
		total := 0
		type pair struct {
			vlan string
			n    int
		}
		ps := make([]pair, 0, len(r.ArpTable))
		for vlan, ips := range r.ArpTable {
			n := len(ips)
			total += n
			ps = append(ps, pair{vlan: vlan, n: n})
		}
		sort.Slice(ps, func(i, j int) bool { return ps[i].vlan < ps[j].vlan })
		fmt.Printf("\n[%s] ARP @ %s: %d entries\n", label, r.IP, total)
		parts := make([]string, 0, len(ps))
		for _, p := range ps {
			parts = append(parts, fmt.Sprintf("%s: %d", p.vlan, p.n))
		}
		fmt.Printf("  by VLAN (%d): %s\n", len(ps), strings.Join(parts, ", "))
	}
}

// PrintMacPollSummary выводит сводку MAC/FDB (MacTableFormatFDB), предупреждения meta, разбивка по VLAN.
func PrintMacPollSummary(results []snmp.PollResult) {
	for _, r := range results {
		label := fmt.Sprint(r.SwitchID)
		if !r.Success {
			err := r.Error
			if err == "" {
				err = "unknown"
			}
			fmt.Printf("\n[%s] MAC @ %s: failed - %s\n", label, r.IP, err)
			continue
		}
		if len(r.MacTable) == 0 {
			fmt.Printf("\n[%s] MAC @ %s: (empty)\n", label, r.IP)
			continue
		}
		fmt.Printf("\n[%s] MAC @ %s:\n", label, r.IP)
		if fmt.Sprint(r.MacTable["format"]) == snmp.MacTableFormatFDB {
			raw, _ := r.MacTable["entries"].([]any)
			fmt.Printf("  MAC/FDB: %d записей\n", len(raw))
			if meta, ok := r.MacTable["meta"].(map[string]any); ok {
				if w := strings.TrimSpace(fmt.Sprint(meta["warning"])); w != "" && w != "<nil>" {
					fmt.Printf("  note: %s\n", w)
				}
			}
			byVLAN := map[string]int{}
			for _, it := range raw {
				row, ok := it.(map[string]any)
				if !ok {
					continue
				}
				byVLAN[fmt.Sprint(row["vlan"])]++
			}
			if len(byVLAN) > 0 {
				keys := make([]string, 0, len(byVLAN))
				for k := range byVLAN {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				parts := make([]string, 0, len(keys))
				for _, k := range keys {
					parts = append(parts, fmt.Sprintf("%s: %d", k, byVLAN[k]))
				}
				fmt.Printf("  by VLAN (%d): %s\n", len(keys), strings.Join(parts, ", "))
			}
		} else {
			keys := make([]string, 0, len(r.MacTable))
			for k := range r.MacTable {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("  %s: %v\n", k, r.MacTable[k])
			}
		}
	}
}
