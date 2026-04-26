package models

import (
	"reflect"
	"testing"
)

func TestHuaweiARPHooksMergeIfIndexToVLANForARP(t *testing.T) {
	ivQBridge := map[string]string{
		"10": "100",
		"20": "200",
	}
	ifName := map[string]string{
		"10": "GigabitEthernet0/0/1",
		"20": "Vlanif220",
		"30": "vlanif300",
		"40": "Loopback0",
	}
	// This input must be ignored by Huawei hook implementation.
	dot1qVlanStaticName := map[string]string{
		"999": "Vlanif999",
	}

	got := (HuaweiARPHooks{}).MergeIfIndexToVLANForARP(ivQBridge, ifName, dot1qVlanStaticName)

	want := map[string]string{
		"10": "100",
		"20": "220",
		"30": "300",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeIfIndexToVLANForARP() mismatch: got=%v want=%v", got, want)
	}

	// Merge should not mutate source qbridge map.
	if ivQBridge["20"] != "200" {
		t.Fatalf("input map ivQBridge was mutated: got %q want %q", ivQBridge["20"], "200")
	}
}
