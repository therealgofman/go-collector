// Package snmp содержит SNMP-клиент на gosnmp, сопоставление моделей с app.yaml и реализации моделей (интерфейсы, ARP, FDB).
package snmp

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type snmpTransport interface {
	Walk(c *Client, baseOID string, community string) (map[string]string, error)
	WalkManyOIDs(c *Client, oids []string, community string, useBulkWalk *bool) (map[string]map[string]string, error)
	WalkWithOptions(c *Client, baseOID string, community string, useBulkWalk *bool) (map[string]string, error)
}

// oidARPPhysAddress — ipNetToMediaPhysAddress (.1.3.6.1.2.1.4.22.1.2). Значение — OCTET STRING;
// snmpwalk может показывать его как Hex-STRING или как STRING с «печатными» байтами — это одно и то же.
const oidARPPhysAddress = "1.3.6.1.2.1.4.22.1.2"

func formatARPPhysAddress(b []byte) string {
	switch len(b) {
	case 6:
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	case 0:
		return ""
	default:
		// не Ethernet (или битый агент) — в БД не тащим сырой string с кракозябрами
		return strings.ToLower(hex.EncodeToString(b))
	}
}

// Client — параметры сессии SNMP v2c к одному IP (таймаут, повторы, community; при Debug — gosnmp.Logger).
type Client struct {
	IP        string
	Community string
	Timeout   time.Duration
	Retries   int
	// GetBulkMaxRepetitions — поле max-repetitions в GETBULK (при обходе через BulkWalk); gosnmp по умолчанию 50; из app.yaml getbulk_max_repetitions.
	GetBulkMaxRepetitions uint32
	// Debug: подробный вывод gosnmp (поле Logger в GoSNMP), флаг CLI -debug-snmp.
	Debug     bool
	OIDTiming bool // логировать длительность каждого walk (флаг CLI -snmp-oid-timing)
	transport snmpTransport
}

// New нормализует IP/community (убирает нулевые байты), задаёт минимальный таймаут 5 с.
func New(ip, comm string, timeoutSec float64, retries int, debug, oidTiming bool, getBulkMaxRepetitions int) *Client {
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	ip = strings.TrimSpace(strings.ReplaceAll(ip, "\x00", ""))
	comm = strings.TrimSpace(strings.ReplaceAll(comm, "\x00", ""))
	bulk := uint32(10)
	if getBulkMaxRepetitions > 0 && getBulkMaxRepetitions <= 255 {
		bulk = uint32(getBulkMaxRepetitions)
	}
	return &Client{
		IP:                    ip,
		Community:             comm,
		Timeout:               time.Duration(timeoutSec * float64(time.Second)),
		Retries:               retries,
		GetBulkMaxRepetitions: bulk,
		Debug:                 debug,
		OIDTiming:             oidTiming,
	}
}

// connect устанавливает UDP-сессию SNMP v2c; community может переопределять базовый (для community@VLAN).
func (c *Client) connect(community string) (*gosnmp.GoSNMP, error) {
	if community == "" {
		community = c.Community
	}
	g := &gosnmp.GoSNMP{
		Target:    c.IP,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   c.Timeout,
		Retries:   c.Retries,
	}
	if c.Debug {
		g.Logger = gosnmp.NewLogger(log.New(os.Stderr, "gosnmp ", log.LstdFlags))
	}
	// BulkWalk шлёт GETBULK с max-repetitions; в gosnmp по умолчанию 50 — часто больше, чем переносят агенты
	// (Junos, Huawei VRP и др.), ответ не приходит → «request timeout». net-snmp snmpbulkwalk по умолчанию -Cr10.
	// Обычный snmpwalk — это GETNEXT, не bulk, поэтому «в консоли ок» при сравнении с BulkWalk в коде.
	g.MaxRepetitions = c.GetBulkMaxRepetitions

	if err := g.Connect(); err != nil {
		return nil, err
	}
	return g, nil
}

// pduToString преобразует значение PDU в строку: для OCTET STRING в основном как сырые байты,
// исключение — OID ARP PhysAddress, где всегда канонизируем в вид xx:xx:... (или hex при len≠6).
func pduToString(v gosnmp.SnmpPDU, baseOID string) string {
	switch x := v.Value.(type) {
	case []byte:
		if baseOID == oidARPPhysAddress {
			return formatARPPhysAddress(x)
		}
		return string(x)
	case string:
		// редко, но на ARP OID иногда приходит как строка из ровно 6 октетов (в walk — «STRING: lAj&W@»)
		if baseOID == oidARPPhysAddress && len(x) == 6 {
			return formatARPPhysAddress([]byte(x))
		}
		return x
	default:
		return fmt.Sprint(v.Value)
	}
}

// Walk выполняет один обход дерева под baseOID с политикой GETNEXT.
func (c *Client) Walk(baseOID string, community string) (map[string]string, error) {
	return c.WalkWithOptions(baseOID, community, nil)
}

// WalkWithOptions выполняет один обход дерева под baseOID с режимом GETNEXT/GETBULK.
func (c *Client) WalkWithOptions(baseOID string, community string, useBulkWalk *bool) (map[string]string, error) {
	if c.transport != nil {
		return c.transport.WalkWithOptions(c, baseOID, community, useBulkWalk)
	}
	g, err := c.connect(community)
	if err != nil {
		return nil, fmt.Errorf("snmp connect ip=%s: %w", c.IP, err)
	}
	defer g.Conn.Close()
	return c.walkWithConn(g, baseOID, useBulkWalk)
}

// walkWithConn — обход поддерева baseOID: Walk (GETNEXT) или BulkWalk (GETBULK). useBulkWalk: nil/false* → GETNEXT, true* → GETBULK.
func (c *Client) walkWithConn(g *gosnmp.GoSNMP, baseOID string, useBulkWalk *bool) (map[string]string, error) {
	out := map[string]string{}
	walkFn := g.Walk // GETNEXT
	doBulk := false
	if useBulkWalk != nil {
		doBulk = *useBulkWalk
	}
	if doBulk {
		walkFn = g.BulkWalk
	}
	start := time.Now()
	err := walkFn(baseOID, func(pdu gosnmp.SnmpPDU) error {
		n := strings.TrimPrefix(pdu.Name, "."+baseOID+".")
		n = strings.TrimPrefix(n, baseOID+".")
		if n == pdu.Name {
			return nil
		}
		out[n] = pduToString(pdu, baseOID)
		return nil
	})
	if c.OIDTiming {
		log.Printf("snmp oid timing ip=%s oid=%s getbulk_walk=%v duration=%s err=%v", c.IP, baseOID, doBulk, time.Since(start).Round(time.Millisecond), err)
	}
	if err != nil {
		mode := walkModeName(doBulk)
		// gosnmp отдаёт только «request timeout (after N retries)» — без OID; контекст добавляем здесь.
		return nil, fmt.Errorf("snmp %s ip=%s oid=%s: %w", mode, c.IP, baseOID, err)
	}
	return out, nil
}

func walkModeName(doBulk bool) string {
	if doBulk {
		return "getbulk_walk"
	}
	return "getnext_walk"
}

// WalkMany последовательно обходит несколько OID на одном TCP/UDP-сокете (оптимизация против отдельного Connect на OID).
func (c *Client) WalkMany(oids []string, community string) (map[string]map[string]string, error) {
	return c.WalkManyOIDs(oids, community, nil)
}

// WalkManyOIDs обходит несколько базовых OID на одном соединении.
// useBulkWalk: nil или указатель на false — для каждого OID используется Walk (GETNEXT); true — BulkWalk (GETBULK) с Client.GetBulkMaxRepetitions.
func (c *Client) WalkManyOIDs(oids []string, community string, useBulkWalk *bool) (map[string]map[string]string, error) {
	if c.transport != nil {
		return c.transport.WalkManyOIDs(c, oids, community, useBulkWalk)
	}
	g, err := c.connect(community)
	if err != nil {
		return nil, fmt.Errorf("snmp connect ip=%s: %w", c.IP, err)
	}
	defer g.Conn.Close()
	out := make(map[string]map[string]string, len(oids))
	for _, oid := range oids {
		tbl, err := c.walkWithConn(g, oid, useBulkWalk)
		if err != nil {
			return nil, err
		}
		out[oid] = tbl
	}
	return out, nil
}

// Identity читает sysDescr и sysObjectID (1.3.6.1.2.1.1.1.0 и 1.3.6.1.2.1.1.2.0) для выбора модели по правилам app.yaml.
func (c *Client) Identity() DeviceIdentity {
	g, err := c.connect("")
	if err != nil {
		return DeviceIdentity{Error: fmt.Sprintf("snmp connect ip=%s: %v", c.IP, err)}
	}
	defer g.Conn.Close()
	pkt, err := g.Get([]string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0"})
	if err != nil {
		return DeviceIdentity{Error: fmt.Sprintf("snmp get ip=%s oids=sysDescr.0,sysObjectID.0: %v", c.IP, err)}
	}
	if len(pkt.Variables) < 2 {
		return DeviceIdentity{Error: "incomplete identity response"}
	}
	return DeviceIdentity{
		SysDescr:    pduToString(pkt.Variables[0], "1.3.6.1.2.1.1.1.0"),
		SysObjectID: pduToString(pkt.Variables[1], "1.3.6.1.2.1.1.2.0"),
	}
}

// canonicalOID нормализует строку OID (ведущая точка, лишние нули в сегментах) для сравнения с match_sysobjectid
func canonicalOID(s string) string {
	s = strings.TrimSpace(strings.TrimPrefix(s, "."))
	if s == "" {
		return s
	}
	parts := strings.Split(s, ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return s
		}
		out = append(out, strconv.Itoa(v))
	}
	return strings.Join(out, ".")
}

// ResolveModelID перебирает правила snmp_switch_models: enabled, match_sysobjectid (только строка),
// match_sysdescr (regex с ignorecase/dotall по умолчанию). Возвращает первый подошедший id или "".
func ResolveModelID(id DeviceIdentity, rules []ModelRule) string {
	if id.Error != "" {
		return ""
	}
	oid := canonicalOID(id.SysObjectID)
	for _, r := range rules {
		modelID := strings.TrimSpace(r.ID)
		if modelID == "" || !r.Enabled {
			continue
		}
		if ruleMatchesIdentity(r, id, oid) {
			return modelID
		}
	}
	return ""
}

func ruleMatchesIdentity(r ModelRule, id DeviceIdentity, canonicalSysObjectID string) bool {
	if x := strings.TrimSpace(r.MatchSysObjectID); x != "" && canonicalOID(x) == canonicalSysObjectID {
		return true
	}
	pat := strings.TrimSpace(r.MatchSysDescr)
	if pat == "" {
		return false
	}
	prefix := regexFlagsPrefix(r)
	// - ignorecase defaults to true
	// - dotall defaults to true ('.' also matches newlines)
	re, err := regexp.Compile(prefix + pat)
	if err != nil {
		return false
	}
	return re.MatchString(id.SysDescr)
}

func regexFlagsPrefix(r ModelRule) string {
	ignoreCase := true
	if r.IgnoreCase != nil {
		ignoreCase = *r.IgnoreCase
	}
	dotAll := true
	if r.MatchSysDescrDotAll != nil {
		dotAll = *r.MatchSysDescrDotAll
	}
	prefix := "(?"
	if ignoreCase {
		prefix += "i"
	}
	if dotAll {
		prefix += "s"
	}
	prefix += ")"
	return prefix
}
