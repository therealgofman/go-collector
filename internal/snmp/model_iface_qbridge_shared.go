package snmp

import (
	"regexp"
	"strconv"
	"strings"
)

// -------------------------------- Q-BRIDGE (общие OID и разбор current VLAN tables) ----------------

var ifaceQBridgeCurrentOIDs = map[string]string{
	"dot1qVlanCurrentEgressPorts":   "1.3.6.1.2.1.17.7.1.4.2.1.4",
	"dot1qVlanCurrentUntaggedPorts": "1.3.6.1.2.1.17.7.1.4.2.1.5",
	"dot1qPvid":                     "1.3.6.1.2.1.17.7.1.4.5.1.1",
}

var ifaceQBridgeStaticOIDs = map[string]string{
	"dot1qVlanStaticEgressPorts":   "1.3.6.1.2.1.17.7.1.4.3.1.2",
	"dot1qVlanStaticUntaggedPorts": "1.3.6.1.2.1.17.7.1.4.3.1.4",
	"dot1qPvid":                    "1.3.6.1.2.1.17.7.1.4.5.1.1",
}

var _ = ifaceQBridgeStaticOIDs // TODO: будет использоваться в других Collector'ах.

var (
	ifaceQBridgeCurrentKeyStrip = regexp.MustCompile(`^\d+\.`)
	ifaceQBridgeCurrentVIDInner = regexp.MustCompile(`^\D+(\d+)\D+$`)
)

func mergeIfaceOIDMaps(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// qBridgeCurrentVIDFromWalkKey извлекает номер VLAN из суффикса OID.
func ifaceQBridgeCurrentVIDFromWalkKey(key string) int {
	s := strings.TrimSpace(key)
	s = ifaceQBridgeCurrentKeyStrip.ReplaceAllString(s, "")
	if m := ifaceQBridgeCurrentVIDInner.FindStringSubmatch(s); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		return v
	}
	v, err := strconv.Atoi(s)
	if err != nil || v == 0 {
		return 0
	}
	return v
}

// QBridgeRawVLANTables декодирует current egress/untagged bitmask и добавляет значения dot1qPvid в egress.
func ifaceQBridgeRawVLANTables(
	egressWalk map[string]string,
	untagWalk map[string]string,
	pvidWalk map[string]string,
	bef bool,
) (map[int][]string, map[int][]string) {
	pe := map[int][]string{}
	pu := map[int][]string{}
	for key, rawE := range egressWalk {
		vid := ifaceQBridgeCurrentVIDFromWalkKey(key)
		if vid == 0 {
			continue
		}
		eArr := bitmaskToArrayWithBEF(rawE, bef)
		rawU := untagWalk[key]
		uArr := bitmaskToArrayWithBEF(rawU, bef)
		if len(uArr) < len(eArr) {
			pad := make([]string, len(eArr))
			copy(pad, uArr)
			uArr = pad
		} else if len(eArr) < len(uArr) {
			pad := make([]string, len(uArr))
			copy(pad, eArr)
			eArr = pad
		}
		pe[vid] = eArr
		pu[vid] = uArr
	}
	for vid, arr := range pe {
		want := strconv.Itoa(vid)
		for pkey, pval := range pvidWalk {
			if strings.TrimSpace(pval) != want {
				continue
			}
			bp, err := strconv.Atoi(strings.TrimSpace(pkey))
			if err != nil || bp < 1 || bp > len(arr) {
				continue
			}
			arr[bp-1] = "1"
		}
	}
	return pe, pu
}
