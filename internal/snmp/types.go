package snmp

// DeviceIdentity — результат SNMP GET sysDescr.0 и sysObjectID.0
type DeviceIdentity struct {
	SysDescr    string
	SysObjectID string
	Error       string
}

// PollResult — единый контейнер результата опроса одного свитча для poll и persist
// Заполняется только релевантными для режима полями: Interfaces, ArpTable или MacTable.
type PollResult struct {
	SwitchID    any
	IP          string
	Success     bool
	Error       string
	SysDescr    string
	SysObjectID string
	RawSwitch   map[string]any
	Interfaces  map[string]any
	ArpTable    map[string]map[string]string
	MacTable    map[string]any
}

// MacTableFormatFDB — значение ключа "format" в map, который возвращает CollectMAC для FDB:
// поля entries ([]any строк) и meta (obsolete_by_vlan, warning и т.д.).
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
	CollectInterfaces() (map[string]any, error)
	CollectARP() (map[string]map[string]string, error)
	CollectMAC(*MacDbContext) (map[string]any, error)
}

// VendorIfaceCollector — стратегия сбора портов/VLAN по SNMP для любой модели;
// подставляется в модель из фабрики или теста (композиция вместо встраивания ciscoL2/huawei*).
type VendorIfaceCollector interface {
	CollectInterfaces(c *Client) (map[string]any, error)
}

// VendorIfaceEnricher — дополнительный этап после базового сбора интерфейсов.
// Используется для дообогащения ports (например port-security, STP, LLDP и т.д.).
type VendorIfaceEnricher interface {
	EnrichInterfaces(c *Client, ports map[string]any) error
}

// VendorARPCollector — стратегия сбора ARP: группировка vlan → (ip → mac).
type VendorARPCollector interface {
	CollectARP(c *Client) (map[string]map[string]string, error)
}

// VendorMACCollector — стратегия сбора MAC/FDB (контракт см. CollectMAC у Model).
// Реализация по умолчанию: NewBridgeMIBMAC (model_mac_bridge.go).
type VendorMACCollector interface {
	CollectMAC(c *Client, ctx *MacDbContext) (map[string]any, error)
}
