// Package poll запускает SNMP-опрос пачки свитчей: выбор модели, вызов Collect* в воркер-пуле, прогресс в консоли.
package poll

import (
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

// RunBatch обрабатывает все свитчи в пуле воркеров (Concurrency), печатает heartbeat по таймеру,
// собирает срез PollResult в исходном порядке списка switches.
func RunBatch(switches []snmp.SwitchRow, kind string, opt Options) []snmp.PollResult {
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
	var wg sync.WaitGroup
	start := time.Now()
	var done atomic.Int64
	var inProgress atomic.Int64
	stop := make(chan struct{})
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		ticker := time.NewTicker(time.Duration(opt.ProgressIntervalS * float64(time.Second)))
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
	}()
	// фиксированный пул воркеров и ограниченная очередь вместо одной goroutine на свитч —
	// так нагрузка по памяти и сокетам предсказуема при десятках тысяч устройств.
	type job struct {
		idx int
		sw  snmp.SwitchRow
	}
	workerCount := opt.Concurrency
	if workerCount > total {
		workerCount = total
	}
	// Небольшая буферизованная очередь: поступление задач и обработка идут параллельно без неограниченного роста очереди.
	jobs := make(chan job, workerCount*4)
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processJob := func(j job) {
				inProgress.Add(1)
				defer inProgress.Add(-1)
				swStart := time.Now()
				if opt.LogPerSwitch {
					ip := j.sw.IP
					s := sid(j.sw)
					fmt.Printf("  -> %s start: switch_id=%s, ip=%s\n", label, s, ip)
				}
				res[j.idx] = runOne(j.sw, kind, opt)
				st := "ok"
				if !res[j.idx].Success {
					st = "fail"
				}
				if opt.LogPerSwitch {
					ip := j.sw.IP
					s := sid(j.sw)
					fmt.Printf(
						"  <- %s done: switch_id=%s, ip=%s, status=%s, elapsed=%.1fs%s\n",
						label,
						s,
						ip,
						st,
						time.Since(swStart).Seconds(),
						func() string {
							if res[j.idx].Error == "" {
								return ""
							}
							return ", err=" + res[j.idx].Error
						}(),
					)
				}
				done.Add(1)
			}
			for j := range jobs {
				processJob(j)
			}
		}()
	}
	for i, sw := range switches {
		jobs <- job{idx: i, sw: sw}
	}
	close(jobs)
	wg.Wait()
	close(stop)
	hbWG.Wait()
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
