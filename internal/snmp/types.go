package snmp

// DeviceIdentity — результат SNMP GET sysDescr.0 и sysObjectID.0
type DeviceIdentity struct {
	SysDescr    string
	SysObjectID string
	Error       string
}

// ModelRule - правило сопоставления устройства с моделью.
type ModelRule struct {
	ID                  string `yaml:"id"`
	Enabled             bool   `yaml:"enabled"`
	MatchSysObjectID    string `yaml:"match_sysobjectid"`
	MatchSysDescr       string `yaml:"match_sysdescr"`
	IgnoreCase          *bool  `yaml:"ignorecase"`
	MatchSysDescrDotAll *bool  `yaml:"match_sysdescr_dotall"`
}

// PortPersistOp - дополнительная persist-операция на уровне порта.
type PortPersistOp struct {
	Query  string
	Params map[string]string
}

// InterfacePort - типизированное представление порта интерфейсов.
type InterfacePort struct {
	Name      string
	IfIndex   int
	Descr     string
	Disabled  bool
	Tagged    bool
	VLANs     map[int]int
	Persist   []PortPersistOp
	Extra     map[string]string
}

// InterfacePorts - коллекция интерфейсов по ключу порта (ifIndex или vendor name).
type InterfacePorts map[string]InterfacePort

// MACEntry - типизированная строка FDB.
type MACEntry struct {
	IfIndex int
	VLAN    int
	VLANID  int
	PortID  int
	MAC     string
	Status  int
}

// MACMeta - метаданные результата MAC/FDB.
type MACMeta struct {
	ObsoleteByVLAN            bool
	Warning                   string
	FallbackVLANIfIndexCounts map[int]map[int]int
}

// MACTable - типизированный контейнер MAC/FDB.
type MACTable struct {
	Format  string
	Entries []MACEntry
	Meta    MACMeta
}

// SwitchRow - типизированная строка свитча для poll/persist.
type SwitchRow struct {
	ID       int
	IP       string
	Comm     string
	DomainID string
	HostName string
}

// PollResult — единый контейнер результата опроса одного свитча для poll и persist
// Заполняется только релевантными для режима полями: Interfaces, ArpTable или MacTable.
type PollResult struct {
	SwitchID    string
	IP          string
	Success     bool
	Error       string
	SysDescr    string
	SysObjectID string
	Switch      SwitchRow
	Interfaces  InterfacePorts
	ArpSkipped  bool
	ArpTable    map[string]map[string]string
	MacTable    MACTable
}

// MacTableFormatFDB — формат результата CollectMAC для FDB:
// используется вместе с полями MACTable.Entries и MACTable.Meta.
// Это метка контракта для persist/display
const MacTableFormatFDB = "mac_fdb"

// MacDbContext — данные из БД, нужные для сбора MAC/FDB и режима community@VLAN (idxcom):
// соответствия ifIndex→port_id, ifIndex→native VLAN, список VLAN для отдельных walk’ов.
// Заполняется в db.Repository.BuildMACDBContext запросами get_ifindex_to_port_id, get_ifindex_untagged_vlan, get_vlan_list_for_mac_idxcom
type MacDbContext struct {
	IfIndexToPortID       map[int]int
	IfIndexToUntaggedVLAN map[int]int
	IdxcomVLANWalks       [][2]int
}

// Model — обязательный контракт для типа, который возвращает models.CreateModel и что опрашивает poll/persist.
// Менять сигнатуры методов нельзя без правок всех вызовов; внутри модели допускается делегирование в Vendor*Collector.
type Model interface {
	CollectInterfaces() (InterfacePorts, error)
	CollectARP() (map[string]map[string]string, error)
	CollectMAC(*MacDbContext) (MACTable, error)
}

// VendorIfaceCollector — стратегия сбора портов/VLAN по SNMP для любой модели;
// подставляется в модель из фабрики или теста (композиция вместо встраивания ciscoL2/huawei*).
type VendorIfaceCollector interface {
	CollectInterfaces(c *Client) (InterfacePorts, error)
}

// VendorIfaceEnricher — дополнительный этап после базового сбора интерфейсов.
// Используется для дообогащения ports (например port-security, STP, LLDP и т.д.).
type VendorIfaceEnricher interface {
	EnrichInterfaces(c *Client, ports InterfacePorts) error
}

// VendorARPCollector — стратегия сбора ARP: группировка vlan → (ip → mac).
type VendorARPCollector interface {
	CollectARP(c *Client) (map[string]map[string]string, error)
}

// VendorMACCollector — стратегия сбора MAC/FDB (контракт см. CollectMAC у Model).
// Реализация по умолчанию: NewBridgeMIBMAC (model_mac_bridge.go).
type VendorMACCollector interface {
	CollectMAC(c *Client, ctx *MacDbContext) (MACTable, error)
}
