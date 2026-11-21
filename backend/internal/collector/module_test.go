package collector

import (
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestRequestRejectsIPHostID(t *testing.T) {
	err := (Request{ScanID: "scan-1", AttemptID: "attempt-1", HostID: "127.0.0.1", ModuleID: "host_identity", Profile: domain.ProfileQuick, PolicyVersion: "0.1.0"}).Validate()
	if err == nil {
		t.Fatal("IP host_id accepted")
	}
}

func TestRequestAcceptsRegisteredHost(t *testing.T) {
	err := (Request{ScanID: "scan-1", AttemptID: "attempt-1", HostID: "linux-test-001", ModuleID: "host_identity", Profile: domain.ProfileQuick, PolicyVersion: "0.1.0"}).Validate()
	if err != nil {
		t.Fatal(err)
	}
}
