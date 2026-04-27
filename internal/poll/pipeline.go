// Package poll запускает SNMP-опрос пачки свитчей: выбор модели, вызов Collect* в воркер-пуле, прогресс в консоли.
package poll

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go-collector/internal/snmp"
	snmpmodels "go-collector/internal/snmp/models"
)

// Options передаёт правила моделей из app.yaml, параметры SNMP и контексты MAC по switch_id.
type Options struct {
	Rules                 []snmp.ModelRule
	Concurrency           int
	DebugSNMP             bool
	TimeoutSec            float64
	Retries               int
	ProgressIntervalS     float64
	MacCtxBySID           map[int]*snmp.MacDbContext
	LogPerSwitch          bool
	OIDTiming             bool
	GetBulkMaxRepetitions int // GETBULK max-repetitions для BulkWalk (app.snmp.getbulk_max_repetitions)
}

// sid извлекает идентификатор свитча из строки БД (d_switch_id либо switch_id либо ip).
func sid(sw snmp.SwitchRow) string {
	if sw.ID > 0 {
		return strconv.Itoa(sw.ID)
	}
	if sw.IP != "" {
		return sw.IP
	}
	return "unknown"
}

// runOne выполняет один полный цикл для свитча: CreateModel, затем CollectInterfaces / CollectARP / CollectMAC
// в зависимости от kind; для MAC подставляет MacDbContext из opt.MacCtxBySID.
func runOne(sw snmp.SwitchRow, kind string, opt Options) snmp.PollResult {
	ip, comm := sw.IP, sw.Comm
	idv := sid(sw)
	if ip == "" || comm == "" {
		return snmp.PollResult{SwitchID: idv, IP: ip, Success: false, Error: "missing_ip_or_comm", Switch: sw}
	}
	model, ident, errMsg := snmpmodels.CreateModel(ip, comm, opt.Rules, opt.DebugSNMP, opt.TimeoutSec, opt.Retries, opt.OIDTiming, opt.GetBulkMaxRepetitions)
	if errMsg != "" {
		return snmp.PollResult{
			SwitchID: idv, IP: ip, Success: false, Error: errMsg, Switch: sw,
			SysDescr: ident.SysDescr, SysObjectID: ident.SysObjectID,
		}
	}
	out := snmp.PollResult{
		SwitchID: idv, IP: ip, Success: true, Switch: sw,
		SysDescr: ident.SysDescr, SysObjectID: ident.SysObjectID,
	}
	switch kind {
	case "interfaces":
		v, err := model.CollectInterfaces()
		if err != nil {
			out.Success = false
			out.Error = err.Error()
		} else {
			out.Interfaces = v
		}
	case "arp":
		v, err := model.CollectARP()
		if err != nil {
			out.Success = false
			out.Error = err.Error()
		} else {
			out.ArpTable = v
			type arpNoopDetector interface {
				IsArpNoop() bool
			}
			if detector, ok := model.(arpNoopDetector); ok {
				out.ArpSkipped = detector.IsArpNoop()
			}
		}
	case "mac":
		var ctx *snmp.MacDbContext
		s := sw.ID
		if s > 0 && opt.MacCtxBySID != nil {
			ctx = opt.MacCtxBySID[s]
		}
		v, err := model.CollectMAC(ctx)
		if err != nil {
			out.Success = false
			out.Error = err.Error()
		} else {
			out.MacTable = v
		}
	}
	return out
}

func startHeartbeat(label string, total int, interval time.Duration, start time.Time, done, inProgress *atomic.Int64) func() {
	stop := make(chan struct{})
	var hbWG sync.WaitGroup
	hbWG.Go(func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				fmt.Printf(
					"  ... %s still running: done %d/%d, elapsed %.0fs, in_progress=%d ...\n",
					label,
					done.Load(),
					total,
					time.Since(start).Seconds(),
					inProgress.Load(),
				)
			}
		}
	})
	return func() {
		close(stop)
		hbWG.Wait()
	}
}

func startPerSwitchLogger(enabled bool, buffer int) (func(string), func()) {
	if !enabled {
		return func(string) {}, func() {}
	}
	if buffer <= 0 {
		buffer = 64
	}
	logs := make(chan string, buffer)
	var logWG sync.WaitGroup
	logWG.Go(func() {
		for msg := range logs {
			fmt.Println(msg)
		}
	})
	logf := func(msg string) {
		select {
		case logs <- msg:
		default:
			// На большой нагрузке не блокируем workers из-за stdout.
		}
	}
	return logf, func() {
		close(logs)
		logWG.Wait()
	}
}

// RunBatch обрабатывает все свитчи в пуле воркеров (Concurrency), печатает heartbeat по таймеру,
// собирает срез PollResult в исходном порядке списка switches.
// Поддерживает раннюю остановку по context.
func RunBatch(ctx context.Context, switches []snmp.SwitchRow, kind string, opt Options) []snmp.PollResult {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 20
	}
	if opt.ProgressIntervalS <= 0 {
		opt.ProgressIntervalS = 30
	}
	label := "SNMP " + kind
	total := len(switches)
	if total == 0 {
		return []snmp.PollResult{}
	}
	fmt.Printf(
		"%s: start poll of %d switches (concurrency <=%d), progress every ~%.0fs...\n",
		label,
		total,
		opt.Concurrency,
		opt.ProgressIntervalS,
	)
	res := make([]snmp.PollResult, len(switches))
	for i, sw := range switches {
		res[i] = snmp.PollResult{
			SwitchID: sid(sw),
			IP:       sw.IP,
			Switch:   sw,
			Success:  false,
			Error:    "batch_not_processed",
		}
	}
	var wg sync.WaitGroup
	var collectWG sync.WaitGroup
	start := time.Now()
	var done atomic.Int64
	var inProgress atomic.Int64
	stopHeartbeat := startHeartbeat(
		label,
		total,
		time.Duration(opt.ProgressIntervalS*float64(time.Second)),
		start,
		&done,
		&inProgress,
	)
	defer stopHeartbeat()
	// фиксированный пул воркеров и ограниченная очередь вместо одной goroutine на свитч —
	// так нагрузка по памяти и сокетам предсказуема при десятках тысяч устройств.
	type job struct {
		idx int
		sw  snmp.SwitchRow
	}
	type jobResult struct {
		idx int
		res snmp.PollResult
	}
	workerCount := min(opt.Concurrency, total)
	// Небольшая буферизованная очередь: поступление задач и обработка идут параллельно без неограниченного роста очереди.
	jobs := make(chan job, workerCount*4)
	results := make(chan jobResult, workerCount*4)
	logf, stopLogger := startPerSwitchLogger(opt.LogPerSwitch, workerCount*8)
	defer stopLogger()
	collectWG.Go(func() {
		for item := range results {
			res[item.idx] = item.res
		}
	})
	for range workerCount {
		wg.Go(func() {
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				inProgress.Add(1)
				swStart := time.Now()
				ip := j.sw.IP
				s := sid(j.sw)
				logf(fmt.Sprintf("  -> %s start: switch_id=%s, ip=%s", label, s, ip))
				out := runOne(j.sw, kind, opt)
				st := "ok"
				if !out.Success {
					st = "fail"
				}
				logf(fmt.Sprintf(
					"  <- %s done: switch_id=%s, ip=%s, status=%s, elapsed=%.1fs%s",
					label,
					s,
					ip,
					st,
					time.Since(swStart).Seconds(),
					func() string {
						if out.Error == "" {
							return ""
						}
						return ", err=" + out.Error
					}(),
				))
				select {
				case <-ctx.Done():
					inProgress.Add(-1)
					return
				case results <- jobResult{idx: j.idx, res: out}:
				}
				done.Add(1)
				inProgress.Add(-1)
			}
		})
	}
produceLoop:
	for i, sw := range switches {
		select {
		case <-ctx.Done():
			break produceLoop
		case jobs <- job{idx: i, sw: sw}:
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	collectWG.Wait()
	ok := 0
	for _, r := range res {
		if r.Success {
			ok++
		}
	}
	fmt.Printf(
		"%s: poll done in %.1fs - success %d/%d, failures %d.\n",
		label,
		time.Since(start).Seconds(),
		ok,
		len(res),
		len(res)-ok,
	)
	return res
}
