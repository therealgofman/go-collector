// Command go-collector — CLI-обёртка над пайплайном «конфиг → MySQL → параллельный SNMP → persist».
// Режимы: сбор интерфейсов (VLAN/порт), ARP, MAC/FDB; опционально -switch-id и -dry-run.
package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"sync"

	"go-collector/internal/config"
	"go-collector/internal/db"
	"go-collector/internal/db/persist"
	"go-collector/internal/poll"
	"go-collector/internal/snmp"
)

// toInt безопасно приводит значение из YAML/БД к int; при ошибке возвращает def.
func toInt(v any, def int) int {
	if v == nil {
		return def
	}
	if n, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
		return n
	}
	return def
}

// toFloat приводит значение к float64 (таймауты SNMP из app.yaml).
func toFloat(v any, def float64) float64 {
	if v == nil {
		return def
	}
	if n, err := strconv.ParseFloat(fmt.Sprint(v), 64); err == nil {
		return n
	}
	return def
}

// mapRules преобразует snmp_switch_models из app.yaml ([]any элементов map) в срез правил для snmp.ResolveModelID
func mapRules(raw any) []map[string]any {
	arr, _ := raw.([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// mapRows — тождественное отображение строк из репозитория (явный тип для читаемости main).
func mapRows(rows []map[string]any) []map[string]any { return rows }

// asInt парсит any в int с запасным значением def (статистика persist).
func asInt(v any, def int) int {
	n, err := strconv.Atoi(fmt.Sprint(v))
	if err != nil {
		return def
	}
	return n
}

// asInt64 используется для счётчиков affected rows MySQL в выводе persist.
func asInt64(v any, def int64) int64 {
	n, err := strconv.ParseInt(fmt.Sprint(v), 10, 64)
	if err != nil {
		return def
	}
	return n
}

// asErrors извлекает срез строк из поля prepare_errors (может быть []string или []any).
func asErrors(v any) []string {
	out := []string{}
	raw, ok := v.([]string)
	if ok {
		return raw
	}
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}

func logWarnings(prefix string, warns []string) {
	for _, w := range warns {
		log.Printf("%s: %s", prefix, w)
	}
}

// main загружает YAML, открывает БД, при необходимости строит MacDbContext по каждому свитчу,
// запускает poll.RunBatch для выбранных видов опроса и вызывает persist
func main() {
	var collectInterfaces, collectARP, collectMAC, debugSNMP, dryRun bool
	var configDir, companyCode string
	var switchID int
	var snmpOIDTiming bool
	flag.StringVar(&companyCode, "company", "", "код компании из config/companies/<код>.yaml (обязательно)")
	flag.StringVar(&configDir, "config-dir", "config", "каталог с app.yaml и подкаталогом companies/")
	flag.BoolVar(&collectInterfaces, "collect-interfaces", false, "собирать интерфейсы")
	flag.BoolVar(&collectARP, "collect-arp", false, "собирать ARP")
	flag.BoolVar(&collectMAC, "collect-mac", false, "собирать MAC/FDB")
	flag.BoolVar(&debugSNMP, "debug-snmp", false, "отладочный вывод SNMP")
	flag.BoolVar(&snmpOIDTiming, "snmp-oid-timing", false, "логировать время обхода по каждому OID SNMP")
	flag.BoolVar(&dryRun, "dry-run", false, "не писать в БД")
	flag.IntVar(&switchID, "switch-id", 0, "один свитч по id (точечный режим)")
	flag.Parse()

	if companyCode == "" {
		log.Fatal("укажите -company")
	}
	if !collectInterfaces && !collectARP && !collectMAC {
		collectInterfaces = true
	}

	loader := config.NewLoader(configDir)
	appCfg, err := loader.LoadAppConfig()
	if err != nil {
		log.Fatal(err)
	}
	companyCfg, err := loader.LoadCompany(companyCode)
	if err != nil {
		log.Fatal(err)
	}
	repo, err := db.NewRepository(companyCfg, appCfg)
	if err != nil {
		log.Fatal(err)
	}
	defer repo.Close()
	persistSvc := persist.New(repo)
	fmt.Printf("Запуск %s v%s\n", fmt.Sprint(appCfg.AppSection()["name"]), fmt.Sprint(appCfg.AppSection()["version"]))
	fmt.Printf("Компания: %s\n", fmt.Sprint(companyCfg.Company["name"]))
	if switchID > 0 {
		fmt.Printf("Только switch_id=%d (режим одного свитча)\n", switchID)
	}

	var sidPtr *int
	if switchID > 0 {
		sidPtr = &switchID
	}
	ifaceSw := []map[string]any{}
	arpSw := []map[string]any{}
	if collectInterfaces || collectMAC {
		rows, err := repo.GetSwitchesForPoll(sidPtr)
		if err != nil {
			log.Fatal(err)
		}
		ifaceSw = mapRows(rows)
	}
	if collectARP {
		rows, err := repo.GetSwitchesForPollARP(sidPtr)
		if err != nil {
			log.Fatal(err)
		}
		arpSw = mapRows(rows)
	}

	rules := mapRules(appCfg.Root["snmp_switch_models"])
	if len(rules) == 0 {
		fmt.Println("Внимание: snmp_switch_models в app.yaml пуст — SNMP-опрос не сопоставит ни одного свитча с моделью.")
	}
	getBulkRep := toInt(appCfg.Get("app.snmp.getbulk_max_repetitions", nil), 0)
	if getBulkRep <= 0 {
		getBulkRep = toInt(appCfg.Get("app.snmp.bulk_max_repetitions", 10), 10) // старое имя ключа
	}
	opt := poll.Options{
		Rules:                 rules,
		Concurrency:           toInt(appCfg.Get("app.snmp.poll_concurrency", 20), 20),
		DebugSNMP:             debugSNMP,
		TimeoutSec:            toFloat(appCfg.Get("app.snmp.timeout_default_s", 5), 5),
		Retries:               toInt(appCfg.Get("app.snmp.retries", 3), 3),
		ProgressIntervalS:     toFloat(appCfg.Get("app.snmp.progress_interval_s", 30), 30),
		LogPerSwitch:          debugSNMP,
		OIDTiming:             snmpOIDTiming,
		GetBulkMaxRepetitions: getBulkRep,
	}
	if collectMAC {
		opt.TimeoutSec = toFloat(appCfg.Get("app.snmp.timeout_mac_s", opt.TimeoutSec), opt.TimeoutSec)
		opt.MacCtxBySID = map[int]*snmp.MacDbContext{}
		for _, sw := range ifaceSw {
			id := toInt(sw["d_switch_id"], toInt(sw["switch_id"], 0))
			if id <= 0 {
				continue
			}
			ctx, err := repo.BuildMACDBContext(id)
			if err == nil {
				opt.MacCtxBySID[id] = ctx
			}
		}
	}

	var ifaceRes, arpRes, macRes []snmp.PollResult
	var wg sync.WaitGroup
	if collectInterfaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ifaceRes = poll.RunBatch(ifaceSw, "interfaces", opt)
		}()
	}
	if collectARP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			arpRes = poll.RunBatch(arpSw, "arp", opt)
		}()
	}
	if (collectInterfaces || collectMAC) && len(ifaceSw) == 0 && (!collectARP || len(arpSw) == 0) {
		if switchID > 0 {
			fmt.Printf("Нечего опрашивать (--switch-id %d: нет строки в БД для этого режима).\n", switchID)
		} else {
			fmt.Println("Нечего опрашивать (нет подходящих свитчей).")
		}
		return
	}
	if collectInterfaces || collectMAC {
		fmt.Printf("свитчи (interfaces/mac): %d\n", len(ifaceSw))
	}
	if collectARP {
		fmt.Printf("свитчи (arp): %d\n", len(arpSw))
	}
	if collectMAC {
		wg.Add(1)
		go func() {
			defer wg.Done()
			macRes = poll.RunBatch(ifaceSw, "mac", opt)
		}()
	}
	wg.Wait()

	if collectInterfaces {
		ok := 0
		for _, r := range ifaceRes {
			if r.Success {
				ok++
			}
		}
		fmt.Printf("интерфейсы собраны: успех %d/%d\n", ok, len(ifaceRes))
		for _, r := range ifaceRes {
			if r.Success && r.Interfaces != nil {
				poll.PrintSwitchInterfaces(r.Interfaces, fmt.Sprint(r.SwitchID), r.IP)
			}
		}
		if dryRun {
			fmt.Println("БД интерфейсов: пропуск (--dry-run)")
		} else {
			stats, err := persistSvc.PersistInterfaces(ifaceRes)
			if err != nil {
				log.Fatal(err)
			}
			if stats["skipped"] == true {
				fmt.Println("БД интерфейсов: пропуск (только чтение)")
			} else {
				warns := asErrors(stats["prepare_errors"])
				fmt.Printf(
					"БД интерфейсов: сохранено — связи vlan/порт=%d, свитчи=%d, предупреждений=%d\n",
					asInt(stats["vlan_links"], 0),
					asInt(stats["switches_processed"], 0),
					len(warns),
				)
				logWarnings("ПРЕДУПРЕЖДЕНИЕ persist интерфейсов", warns)
			}
		}
	}
	if collectARP {
		poll.PrintArpPollSummary(arpRes)
		if dryRun {
			fmt.Println("БД ARP: пропуск (--dry-run)")
		} else {
			stats, err := persistSvc.PersistARP(arpRes)
			if err != nil {
				log.Fatal(err)
			}
			if stats["skipped"] == true {
				fmt.Println("БД ARP: пропуск (только чтение)")
			} else {
				warns := asErrors(stats["prepare_errors"])
				fmt.Printf(
					"БД ARP: сохранено — upsert=%d, сумма affected rows MySQL=%d, свитчи=%d, предупреждений prepare=%d\n",
					asInt(stats["rows_upserted"], 0),
					asInt64(stats["mysql_affected_rows_sum"], int64(asInt(stats["rows_upserted"], 0))),
					asInt(stats["switches_processed"], 0),
					len(warns),
				)
				logWarnings("ПРЕДУПРЕЖДЕНИЕ prepare ARP", warns)
			}
		}
	}
	if collectMAC {
		poll.PrintMacPollSummary(macRes)
		stats, err := persistSvc.PersistMAC(macRes, dryRun)
		if err != nil {
			log.Fatal(err)
		}
		if dryRun {
			fmt.Println("БД MAC: dry-run (без записи) — тот же prepare, что при сохранении; предупреждения ниже при наличии")
			if stats["skipped"] == true {
				fmt.Println("БД MAC: prepare пропущен (только чтение; для полного dry-run prepare нужна доступная на запись конфигурация компании)")
			} else {
				warns := asErrors(stats["prepare_errors"])
				fmt.Printf(
					"БД MAC: dry-run — было бы upsert=%d, свитчи=%d, предупреждений=%d\n",
					asInt(stats["rows_upserted"], 0),
					asInt(stats["switches_processed"], 0),
					len(warns),
				)
				logWarnings("ПРЕДУПРЕЖДЕНИЕ persist MAC", warns)
			}
		} else {
			if stats["skipped"] == true {
				fmt.Println("БД MAC: пропуск (только чтение или нет upsert_mac_forward в yaml компании)")
			} else {
				warns := asErrors(stats["prepare_errors"])
				fmt.Printf(
					"БД MAC: сохранено — upsert=%d, помечено устаревших=%d, свитчи=%d, предупреждений=%d\n",
					asInt(stats["rows_upserted"], 0),
					asInt64(stats["obsolete_rows_affected"], 0),
					asInt(stats["switches_processed"], 0),
					len(warns),
				)
				logWarnings("ПРЕДУПРЕЖДЕНИЕ persist MAC", warns)
			}
		}
	}
}
