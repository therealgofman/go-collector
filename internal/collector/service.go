package collector

import (
	"context"
	"fmt"
	"log"
	"time"

	"go-collector/internal/config"
	"go-collector/internal/db"
	"go-collector/internal/db/persist"
	"go-collector/internal/poll"
	"go-collector/internal/snmp"
)

type RunOptions struct {
	CompanyCode       string
	ConfigDir         string
	CollectInterfaces bool
	CollectARP        bool
	CollectMAC        bool
	DebugSNMP         bool
	DryRun            bool
	SwitchID          int
	SNMPOIDTiming     bool
	PollBatchSize     int
}

type Service struct {
	opts RunOptions
}

type runtimeState struct {
	repo       *db.Repository
	persistSvc *persist.Service
	snmpCfg    config.AppSNMP
	pollOpt    poll.Options
	ifaceSw    []snmp.SwitchRow
	arpSw      []snmp.SwitchRow
}

func NewService(opts RunOptions) *Service {
	return &Service{opts: opts}
}

func (s *Service) Run() error {
	s.applyDefaultModes()
	state, cleanup, err := s.buildRuntimeState()
	if err != nil {
		return err
	}
	defer cleanup()

	if !s.ensurePollTargets(state) {
		return nil
	}
	s.printSwitchCounts(state)
	if err := s.runInterfaces(state); err != nil {
		return err
	}
	if err := s.runARP(state); err != nil {
		return err
	}
	if err := s.runMAC(state); err != nil {
		return err
	}
	return nil
}

func (s *Service) applyDefaultModes() {
	if !s.opts.CollectInterfaces && !s.opts.CollectARP && !s.opts.CollectMAC {
		s.opts.CollectInterfaces = true
	}
}

func (s *Service) buildRuntimeState() (*runtimeState, func(), error) {
	loader := config.NewLoader(s.opts.ConfigDir)
	appCfg, err := loader.LoadAppConfig()
	if err != nil {
		return nil, nil, err
	}
	companyCfg, err := loader.LoadCompany(s.opts.CompanyCode)
	if err != nil {
		return nil, nil, err
	}
	sqlDB, err := db.OpenMySQLDB(companyCfg, appCfg)
	if err != nil {
		return nil, nil, err
	}
	if err := db.PingMySQLDB(sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, nil, err
	}

	repo, err := db.NewRepository(db.Deps{
		DB:      sqlDB,
		Company: companyCfg,
		App:     appCfg,
	})
	if err != nil {
		_ = sqlDB.Close()
		return nil, nil, err
	}

	fmt.Printf("Запуск %s v%s\n", appCfg.App.Name, appCfg.App.Version)
	fmt.Printf("Компания: %s\n", companyCfg.Company.Name)
	if s.opts.SwitchID > 0 {
		fmt.Printf("Только switch_id=%d (режим одного свитча)\n", s.opts.SwitchID)
	}

	var sidPtr *int
	if s.opts.SwitchID > 0 {
		sidPtr = &s.opts.SwitchID
	}

	ifaceSw := []snmp.SwitchRow{}
	arpSw := []snmp.SwitchRow{}
	if s.opts.CollectInterfaces || s.opts.CollectMAC {
		rows, err := repo.GetSwitchesForPoll(sidPtr)
		if err != nil {
			_ = sqlDB.Close()
			return nil, nil, err
		}
		ifaceSw = rows
	}
	if s.opts.CollectARP {
		rows, err := repo.GetSwitchesForPollARP(sidPtr)
		if err != nil {
			_ = sqlDB.Close()
			return nil, nil, err
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
		DebugSNMP:             s.opts.DebugSNMP,
		TimeoutSec:            snmpCfg.TimeoutDefaultS,
		Retries:               snmpCfg.Retries,
		ProgressIntervalS:     snmpCfg.ProgressIntervalS,
		LogPerSwitch:          s.opts.DebugSNMP,
		OIDTiming:             s.opts.SNMPOIDTiming,
		GetBulkMaxRepetitions: snmpCfg.GetBulkMaxRepetitions,
	}
	state := &runtimeState{
		repo:       repo,
		persistSvc: persist.New(repo),
		snmpCfg:    snmpCfg,
		pollOpt:    opt,
		ifaceSw:    ifaceSw,
		arpSw:      arpSw,
	}
	return state, func() { _ = sqlDB.Close() }, nil
}

func (s *Service) ensurePollTargets(state *runtimeState) bool {
	if (s.opts.CollectInterfaces || s.opts.CollectMAC) && len(state.ifaceSw) == 0 && (!s.opts.CollectARP || len(state.arpSw) == 0) {
		if s.opts.SwitchID > 0 {
			fmt.Printf("Нечего опрашивать (--switch-id %d: нет строки в БД для этого режима).\n", s.opts.SwitchID)
		} else {
			fmt.Println("Нечего опрашивать (нет подходящих свитчей).")
		}
		return false
	}
	return true
}

func (s *Service) printSwitchCounts(state *runtimeState) {
	if s.opts.CollectInterfaces || s.opts.CollectMAC {
		fmt.Printf("свитчи (interfaces/mac): %d\n", len(state.ifaceSw))
	}
	if s.opts.CollectARP {
		fmt.Printf("свитчи (arp): %d\n", len(state.arpSw))
	}
}

func (s *Service) runInterfaces(state *runtimeState) error {
	if !s.opts.CollectInterfaces {
		return nil
	}
	okTotal, total := 0, 0
	agg := persist.PersistInterfacesStats{PrepareErrors: []string{}}
	batches := splitSwitchesInBatches(state.ifaceSw, s.opts.PollBatchSize)
	for i, batch := range batches {
		fmt.Printf("interfaces: batch %d/%d (size=%d)\n", i+1, len(batches), len(batch))
		res, err := runBatchWithTimeout(state.snmpCfg, batch, "interfaces", state.pollOpt, i, len(batches))
		if err != nil {
			return err
		}
		total += len(res)
		for _, r := range res {
			if r.Success {
				okTotal++
			}
			if r.Success && r.Interfaces != nil {
				poll.PrintSwitchInterfaces(r.Interfaces, fmt.Sprint(r.SwitchID), r.IP)
			}
		}
		if s.opts.DryRun {
			continue
		}
		stats, err := state.persistSvc.PersistInterfaces(res)
		if err != nil {
			return err
		}
		agg.Skipped = stats.Skipped
		agg.SwitchesProcessed += stats.SwitchesProcessed
		agg.VLANLinks += stats.VLANLinks
		agg.PrepareErrors = append(agg.PrepareErrors, stats.PrepareErrors...)
	}
	fmt.Printf("интерфейсы собраны: успех %d/%d\n", okTotal, total)
	if s.opts.DryRun {
		fmt.Println("БД интерфейсов: пропуск (--dry-run)")
		return nil
	}
	if agg.Skipped {
		fmt.Println("БД интерфейсов: пропуск (только чтение)")
		return nil
	}
	warns := agg.PrepareErrors
	fmt.Printf(
		"БД интерфейсов: сохранено — связи vlan/порт=%d, свитчи=%d, предупреждений=%d\n",
		agg.VLANLinks,
		agg.SwitchesProcessed,
		len(warns),
	)
	logWarnings("ПРЕДУПРЕЖДЕНИЕ persist интерфейсов", warns)
	return nil
}

func (s *Service) runARP(state *runtimeState) error {
	if !s.opts.CollectARP {
		return nil
	}
	agg := persist.PersistARPStats{PrepareErrors: []string{}}
	batches := splitSwitchesInBatches(state.arpSw, s.opts.PollBatchSize)
	for i, batch := range batches {
		fmt.Printf("arp: batch %d/%d (size=%d)\n", i+1, len(batches), len(batch))
		res, err := runBatchWithTimeout(state.snmpCfg, batch, "arp", state.pollOpt, i, len(batches))
		if err != nil {
			return err
		}
		poll.PrintArpPollSummary(res)
		if s.opts.DryRun {
			continue
		}
		stats, err := state.persistSvc.PersistARP(res)
		if err != nil {
			return err
		}
		agg.Skipped = stats.Skipped
		agg.RowsUpserted += stats.RowsUpserted
		agg.MySQLAffectedRows += stats.MySQLAffectedRows
		agg.SwitchesProcessed += stats.SwitchesProcessed
		agg.PrepareErrors = append(agg.PrepareErrors, stats.PrepareErrors...)
	}
	if s.opts.DryRun {
		fmt.Println("БД ARP: пропуск (--dry-run)")
		return nil
	}
	if agg.Skipped {
		fmt.Println("БД ARP: пропуск (только чтение)")
		return nil
	}
	warns := agg.PrepareErrors
	fmt.Printf(
		"БД ARP: сохранено — upsert=%d, сумма affected rows MySQL=%d, свитчи=%d, предупреждений prepare=%d\n",
		agg.RowsUpserted,
		agg.MySQLAffectedRows,
		agg.SwitchesProcessed,
		len(warns),
	)
	logWarnings("ПРЕДУПРЕЖДЕНИЕ prepare ARP", warns)
	return nil
}

func (s *Service) runMAC(state *runtimeState) error {
	if !s.opts.CollectMAC {
		return nil
	}
	agg := persist.PersistMACStats{PrepareErrors: []string{}}
	batches := splitSwitchesInBatches(state.ifaceSw, s.opts.PollBatchSize)
	for i, batch := range batches {
		fmt.Printf("mac: batch %d/%d (size=%d)\n", i+1, len(batches), len(batch))
		macOpt := s.buildMACPollOptions(state, batch)
		res, err := runBatchWithTimeout(state.snmpCfg, batch, "mac", macOpt, i, len(batches))
		if err != nil {
			return err
		}
		poll.PrintMacPollSummary(res)
		stats, err := state.persistSvc.PersistMAC(res, s.opts.DryRun)
		if err != nil {
			return err
		}
		agg.Skipped = stats.Skipped
		agg.RowsUpserted += stats.RowsUpserted
		agg.MySQLAffectedRows += stats.MySQLAffectedRows
		agg.ObsoleteRowsAffected += stats.ObsoleteRowsAffected
		agg.SwitchesProcessed += stats.SwitchesProcessed
		agg.PrepareErrors = append(agg.PrepareErrors, stats.PrepareErrors...)
	}
	if s.opts.DryRun {
		fmt.Println("БД MAC: dry-run (без записи) — тот же prepare, что при сохранении; предупреждения ниже при наличии")
		if agg.Skipped {
			fmt.Println("БД MAC: prepare пропущен (только чтение; для полного dry-run prepare нужна доступная на запись конфигурация компании)")
			return nil
		}
		warns := agg.PrepareErrors
		fmt.Printf(
			"БД MAC: dry-run — было бы upsert=%d, свитчи=%d, предупреждений=%d\n",
			agg.RowsUpserted,
			agg.SwitchesProcessed,
			len(warns),
		)
		logWarnings("ПРЕДУПРЕЖДЕНИЕ persist MAC", warns)
		return nil
	}
	if agg.Skipped {
		fmt.Println("БД MAC: пропуск (только чтение или нет upsert_mac_forward в yaml компании)")
		return nil
	}
	warns := agg.PrepareErrors
	fmt.Printf(
		"БД MAC: сохранено — upsert=%d, помечено устаревших=%d, свитчи=%d, предупреждений=%d\n",
		agg.RowsUpserted,
		agg.ObsoleteRowsAffected,
		agg.SwitchesProcessed,
		len(warns),
	)
	logWarnings("ПРЕДУПРЕЖДЕНИЕ persist MAC", warns)
	return nil
}

func (s *Service) buildMACPollOptions(state *runtimeState, batch []snmp.SwitchRow) poll.Options {
	macOpt := state.pollOpt
	macOpt.TimeoutSec = state.snmpCfg.TimeoutMACS
	macOpt.MacCtxBySID = map[int]*snmp.MacDbContext{}
	for _, sw := range batch {
		if sw.ID <= 0 {
			continue
		}
		ctx, err := state.repo.BuildMACDBContext(sw.ID)
		if err == nil {
			macOpt.MacCtxBySID[sw.ID] = ctx
		}
	}
	return macOpt
}

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

func runBatchWithTimeout(
	snmpCfg config.AppSNMP,
	batch []snmp.SwitchRow,
	kind string,
	opt poll.Options,
	batchIndex int,
	batchesTotal int,
) ([]snmp.PollResult, error) {
	batchCtx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(snmpCfg.PollBatchTimeoutS*float64(time.Second)),
	)
	defer cancel()

	res := poll.RunBatch(batchCtx, batch, kind, opt)
	if batchCtx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf(
			"%s batch %d/%d timed out after %.0fs",
			kind,
			batchIndex+1,
			batchesTotal,
			snmpCfg.PollBatchTimeoutS,
		)
	}
	return res, nil
}
