// Command go-collector — CLI-обёртка над пайплайном «конфиг → MySQL → параллельный SNMP → persist».
package main

import (
	"flag"
	"log"

	"go-collector/internal/collector"
)

func main() {
	var collectInterfaces, collectARP, collectMAC, noDisplay, debugSNMP, dryRun bool
	var configDir, companyCode string
	var switchID int
	var snmpOIDTiming bool
	var pollBatchSize int
	flag.StringVar(&companyCode, "company", "", "код компании из config/companies/<код>.yaml (обязательно)")
	flag.StringVar(&configDir, "config-dir", "config", "каталог с app.yaml и подкаталогом companies/")
	flag.BoolVar(&collectInterfaces, "collect-interfaces", false, "собирать интерфейсы")
	flag.BoolVar(&collectARP, "collect-arp", false, "собирать ARP")
	flag.BoolVar(&collectMAC, "collect-mac", false, "собирать MAC/FDB")
	flag.BoolVar(&noDisplay, "no-display", false, "отключить display-слой (без печати подробных результатов poll)")
	flag.BoolVar(&debugSNMP, "debug-snmp", false, "отладочный вывод SNMP")
	flag.BoolVar(&snmpOIDTiming, "snmp-oid-timing", false, "логировать время обхода по каждому OID SNMP")
	flag.BoolVar(&dryRun, "dry-run", false, "не писать в БД")
	flag.IntVar(&switchID, "switch-id", 0, "один свитч по id (точечный режим)")
	flag.IntVar(&pollBatchSize, "poll-batch-size", 1000, "размер батча свитчей для опроса/persist (защита памяти на больших объёмах)")
	flag.Parse()

	if companyCode == "" {
		log.Fatal("укажите -company")
	}
	if err := collector.NewService(collector.RunOptions{
		CompanyCode:       companyCode,
		ConfigDir:         configDir,
		CollectInterfaces: collectInterfaces,
		CollectARP:        collectARP,
		CollectMAC:        collectMAC,
		NoDisplay:         noDisplay,
		DebugSNMP:         debugSNMP,
		DryRun:            dryRun,
		SwitchID:          switchID,
		SNMPOIDTiming:     snmpOIDTiming,
		PollBatchSize:     pollBatchSize,
	}).Run(); err != nil {
		log.Fatal(err)
	}
}
