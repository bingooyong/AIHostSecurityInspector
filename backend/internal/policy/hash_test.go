package policy

import "testing"

func TestPolicyHashChangesWithLimits(t *testing.T) {
	quick, err := Get("quick")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Hash(quick)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash(quick)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("unstable policy hash")
	}
	quick.Limits.MaxFiles = 1
	c, err := Hash(quick)
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Fatal("limit change did not affect policy hash")
	}
}
