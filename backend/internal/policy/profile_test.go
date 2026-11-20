package policy

import (
	"slices"
	"testing"
)

func TestProfilesAreCumulativeAndDetached(t *testing.T) {
	quick, e := Get("quick")
	if e != nil {
		t.Fatal(e)
	}
	standard, e := Get("standard")
	if e != nil {
		t.Fatal(e)
	}
	deep, e := Get("deep")
	if e != nil {
		t.Fatal(e)
	}
	for _, module := range quick.Modules {
		if !slices.Contains(standard.Modules, module) || !slices.Contains(deep.Modules, module) {
			t.Fatal("dropped quick module", module)
		}
	}
	for _, module := range standard.Modules {
		if !slices.Contains(deep.Modules, module) {
			t.Fatal("deep dropped standard module", module)
		}
	}
	if !deep.ApprovalRequired || !deep.Limits.MaintenanceWindowRequired || deep.Limits.Enforced {
		t.Fatal("deep safety description wrong")
	}
	if slices.Contains(deep.Limits.AllowedPaths, "/") {
		t.Fatal("full disk default")
	}
	ir, e := Get("incident-response")
	if e != nil {
		t.Fatal(e)
	}
	if !ir.ApprovalRequired || slices.Contains(ir.Modules, "yara_scan") {
		t.Fatal("IR expanded into deep")
	}
	deep.Modules[0] = "mutated"
	next, e := Get("deep")
	if e != nil {
		t.Fatal(e)
	}
	if next.Modules[0] == "mutated" {
		t.Fatal("profile shared mutable state")
	}
	if _, e := Get("--exec"); e == nil {
		t.Fatal("unrecognized profile")
	}
}
