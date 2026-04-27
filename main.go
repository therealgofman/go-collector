// Command go-collector — CLI-обёртка над пайплайном «конфиг → MySQL → параллельный SNMP → persist».
// Режимы: сбор интерфейсов (VLAN/порт), ARP, MAC/FDB; опционально -switch-id и -dry-run.
package main

import (
	"flag"
	"fmt"
	"log"

	"go-collector/internal/config"
	"go-collector/internal/db"
	"go-collector/internal/db/persist"
	"go-collector/internal/poll"
	"go-collector/internal/snmp"
)

func splitSwitchesInBatches(items []snmp.SwitchRow, batchSize int) [][]snmp.SwitchRow {
	if len(items) == 0 {
		return [][]snmp.SwitchRow{}
	}
	if batchSize <= 0 {
		return [][]snmp.SwitchRow{items}
	}
	out := make([][]snmp.SwitchRow, 0, (len(items)+batchSize-1)/batchSize)
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}
		out = append(out, items[i:end])
	}
	return out
}

func logWarnings(prefix string, warns []string) {
	for _, w := range warns {
		log.Printf("%s: %s", prefix, w)
	}
}

// main загружает YAML, открывает БД, собирает репозиторий через DI, при необходимости строит MacDbContext по каждому свитчу,
// запускает poll.RunBatch для выбранных видов опроса и вызывает persist
func main() {
	var collectInterfaces, collectARP, collectMAC, debugSNMP, dryRun bool
	var configDir, companyCode string
	var switchID int
	var snmpOIDTiming bool
	var pollBatchSize int
	flag.StringVar(&companyCode, "company", "", "код компании из config/companies/<код>.yaml (обязательно)")
	flag.StringVar(&configDir, "config-dir", "config", "каталог с app.yaml и подкаталогом companies/")
	flag.BoolVar(&collectInterfaces, "collect-interfaces", false, "собирать интерфейсы")
	flag.BoolVar(&collectARP, "collect-arp", false, "собирать ARP")
	flag.BoolVar(&collectMAC, "collect-mac", false, "собирать MAC/FDB")
	flag.BoolVar(&debugSNMP, "debug-snmp", false, "отладочный вывод SNMP")
	flag.BoolVar(&snmpOIDTiming, "snmp-oid-timing", false, "логировать время обхода по каждому OID SNMP")
	flag.BoolVar(&dryRun, "dry-run", false, "не писать в БД")
	flag.IntVar(&switchID, "switch-id", 0, "один свитч по id (точечный режим)")
	flag.IntVar(&pollBatchSize, "poll-batch-size", 1000, "размер батча свитчей для опроса/persist (защита памяти на больших объёмах)")
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
	sqlDB, err := db.OpenMySQLDB(companyCfg, appCfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := db.PingMySQLDB(sqlDB); err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()
	repo, err := db.NewRepository(db.Deps{
		DB:      sqlDB,
		Company: companyCfg,
		App:     appCfg,
	})
	if err != nil {
		log.Fatal(err)
	}
	persistSvc := persist.New(repo)
	fmt.Printf("Запуск %s v%s\n", appCfg.App.Name, appCfg.App.Version)
	fmt.Printf("Компания: %s\n", companyCfg.Company.Name)
	if switchID > 0 {
		fmt.Printf("Только switch_id=%d (режим одного свитча)\n", switchID)
	}

	var sidPtr *int
	if switchID > 0 {
		sidPtr = &switchID
	}
	ifaceSw := []snmp.SwitchRow{}
	arpSw := []snmp.SwitchRow{}
	if collectInterfaces || collectMAC {
		rows, err := repo.GetSwitchesForPoll(sidPtr)
		if err != nil {
			log.Fatal(err)
		}
		ifaceSw = rows
	}
	if collectARP {
		rows, err := repo.GetSwitchesForPollARP(sidPtr)
		if err != nil {
			log.Fatal(err)
		}
		arpSw = rows
	}

	rules := appCfg.SNMPSwitchModels
	if len(rules) == 0 {
		fmt.Println("Внимание: snmp_switch_models в app.yaml пуст — SNMP-опрос не сопоставит ни одного свитча с моделью.")
	}
	snmpCfg := appCfg.SNMPSettings()
	opt := poll.Options{
		Rules:                 rules,
		Concurrency:           snmpCfg.PollConcurrency,
		DebugSNMP:             debugSNMP,
		TimeoutSec:            snmpCfg.TimeoutDefaultS,
		Retries:               snmpCfg.Retries,
		ProgressIntervalS:     snmpCfg.ProgressIntervalS,
		LogPerSwitch:          debugSNMP,
		OIDTiming:             snmpOIDTiming,
		GetBulkMaxRepetitions: snmpCfg.GetBulkMaxRepetitions,
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

	if collectInterfaces {
		okTotal, total := 0, 0
		agg := persist.PersistInterfacesStats{PrepareErrors: []string{}}
		batches := splitSwitchesInBatches(ifaceSw, pollBatchSize)
		for i, batch := range batches {
			// Батчируем, чтобы не держать в памяти результаты по всем свитчам сразу.
			fmt.Printf("interfaces: batch %d/%d (size=%d)\n", i+1, len(batches), len(batch))
			res := poll.RunBatch(batch, "interfaces", opt)
			total += len(res)
			for _, r := range res {
				if r.Success {
					okTotal++
				}
				if r.Success && r.Interfaces != nil {
					poll.PrintSwitchInterfaces(r.Interfaces, fmt.Sprint(r.SwitchID), r.IP)
				}
			}
			if dryRun {
				continue
			}
			stats, err := persistSvc.PersistInterfaces(res)
			if err != nil {
				log.Fatal(err)
			}
			agg.Skipped = stats.Skipped
			agg.SwitchesProcessed += stats.SwitchesProcessed
			agg.VLANLinks += stats.VLANLinks
			agg.PrepareErrors = append(agg.PrepareErrors, stats.PrepareErrors...)
		}
		fmt.Printf("интерфейсы собраны: успех %d/%d\n", okTotal, total)
		if dryRun {
			fmt.Println("БД интерфейсов: пропуск (--dry-run)")
		} else {
			if agg.Skipped {
				fmt.Println("БД интерфейсов: пропуск (только чтение)")
			} else {
				warns := agg.PrepareErrors
				fmt.Printf(
					"БД интерфейсов: сохранено — связи vlan/порт=%d, свитчи=%d, предупреждений=%d\n",
					agg.VLANLinks,
					agg.SwitchesProcessed,
					len(warns),
				)
				logWarnings("ПРЕДУПРЕЖДЕНИЕ persist интерфейсов", warns)
			}
		}
	}
	if collectARP {
		agg := persist.PersistARPStats{PrepareErrors: []string{}}
		batches := splitSwitchesInBatches(arpSw, pollBatchSize)
		for i, batch := range batches {
			fmt.Printf("arp: batch %d/%d (size=%d)\n", i+1, len(batches), len(batch))
			res := poll.RunBatch(batch, "arp", opt)
			poll.PrintArpPollSummary(res)
			if dryRun {
				continue
			}
			stats, err := persistSvc.PersistARP(res)
			if err != nil {
				log.Fatal(err)
			}
			agg.Skipped = stats.Skipped
			agg.RowsUpserted += stats.RowsUpserted
			agg.MySQLAffectedRows += stats.MySQLAffectedRows
			agg.SwitchesProcessed += stats.SwitchesProcessed
			agg.PrepareErrors = append(agg.PrepareErrors, stats.PrepareErrors...)
		}
		if dryRun {
			fmt.Println("БД ARP: пропуск (--dry-run)")
		} else {
			if agg.Skipped {
				fmt.Println("БД ARP: пропуск (только чтение)")
			} else {
				warns := agg.PrepareErrors
				fmt.Printf(
					"БД ARP: сохранено — upsert=%d, сумма affected rows MySQL=%d, свитчи=%d, предупреждений prepare=%d\n",
					agg.RowsUpserted,
					agg.MySQLAffectedRows,
					agg.SwitchesProcessed,
					len(warns),
				)
				logWarnings("ПРЕДУПРЕЖДЕНИЕ prepare ARP", warns)
			}
		}
	}
	if collectMAC {
		agg := persist.PersistMACStats{PrepareErrors: []string{}}
		batches := splitSwitchesInBatches(ifaceSw, pollBatchSize)
		for i, batch := range batches {
			fmt.Printf("mac: batch %d/%d (size=%d)\n", i+1, len(batches), len(batch))
			macOpt := opt
			macOpt.TimeoutSec = snmpCfg.TimeoutMACS
			// Контекст MAC строим только для текущего батча, чтобы не делать N+1 по всем свитчам заранее.
			macOpt.MacCtxBySID = map[int]*snmp.MacDbContext{}
			for _, sw := range batch {
				if sw.ID <= 0 {
					continue
				}
				ctx, err := repo.BuildMACDBContext(sw.ID)
				if err == nil {
					macOpt.MacCtxBySID[sw.ID] = ctx
				}
			}
			res := poll.RunBatch(batch, "mac", macOpt)
			poll.PrintMacPollSummary(res)
			stats, err := persistSvc.PersistMAC(res, dryRun)
			if err != nil {
				log.Fatal(err)
			}
			agg.Skipped = stats.Skipped
			agg.RowsUpserted += stats.RowsUpserted
			agg.MySQLAffectedRows += stats.MySQLAffectedRows
			agg.ObsoleteRowsAffected += stats.ObsoleteRowsAffected
			agg.SwitchesProcessed += stats.SwitchesProcessed
			agg.PrepareErrors = append(agg.PrepareErrors, stats.PrepareErrors...)
		}
		if dryRun {
			fmt.Println("БД MAC: dry-run (без записи) — тот же prepare, что при сохранении; предупреждения ниже при наличии")
			if agg.Skipped {
				fmt.Println("БД MAC: prepare пропущен (только чтение; для полного dry-run prepare нужна доступная на запись конфигурация компании)")
			} else {
				warns := agg.PrepareErrors
				fmt.Printf(
					"БД MAC: dry-run — было бы upsert=%d, свитчи=%d, предупреждений=%d\n",
					agg.RowsUpserted,
					agg.SwitchesProcessed,
					len(warns),
				)
				logWarnings("ПРЕДУПРЕЖДЕНИЕ persist MAC", warns)
			}
		} else {
			if agg.Skipped {
				fmt.Println("БД MAC: пропуск (только чтение или нет upsert_mac_forward в yaml компании)")
			} else {
				warns := agg.PrepareErrors
				fmt.Printf(
					"БД MAC: сохранено — upsert=%d, помечено устаревших=%d, свитчи=%d, предупреждений=%d\n",
					agg.RowsUpserted,
					agg.ObsoleteRowsAffected,
					agg.SwitchesProcessed,
					len(warns),
				)
				logWarnings("ПРЕДУПРЕЖДЕНИЕ persist MAC", warns)
			}
		}
	}
}
