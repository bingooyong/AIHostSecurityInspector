package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
)

func fixtureIntent(t *testing.T) domain.ExecutionIntent {
	t.Helper()
	inv, err := asset.Load(context.Background(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Get(domain.ProfileQuick)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := asset.HashSnapshot(*inv)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := policy.Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	intent := domain.ExecutionIntent{
		SchemaVersion: domain.IntentSchemaVersion, CanonicalVersion: domain.IntentCanonicalVersion,
		RequesterPrincipal: "operator-alice", HostIDs: []string{"linux-test-001"}, IdentityRefs: []string{"hostid-linux-test-001"},
		AssetSnapshotHash: snap, PolicyID: policy.PolicyID, PolicyVersion: policy.PolicyVersion, PolicyHash: policyHash,
		Profile: p.Name, Modules: p.Modules, Tools: p.Tools, AllowedPaths: p.Limits.AllowedPaths,
		ExcludedPaths: p.Limits.ExcludedPaths, ExcludedMountTypes: p.Limits.ExcludedMountTypes,
		Limits: domain.IntentLimits{
			TimeoutSeconds: p.Limits.TimeoutSeconds, MaxConcurrency: p.Limits.MaxConcurrency,
			MaxFiles: p.Limits.MaxFiles, MaxFileSizeBytes: p.Limits.MaxFileSizeBytes,
			IOMaxBytesPerSecond: p.Limits.IOMaxBytesPerSecond, StopOnResourcePressure: true,
		},
		RequiredCapabilities: []string{"linux_proc"}, ValidFrom: "2026-11-20T00:00:00Z", ValidUntil: "2026-11-20T06:00:00Z",
		Mode: domain.ModeReadOnly,
	}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	return intent
}

func approvalTestStore(t *testing.T) (approval.TrustStore, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	reqPub, reqPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	apprPub, apprPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := approval.TrustStore{
		Principals: map[string]approval.Principal{
			"operator-alice": {ID: "operator-alice", KeyID: "key-requester", CanRequest: true},
			"approver-bob":   {ID: "approver-bob", KeyID: "key-approver", CanApprove: true},
		},
		Keys:               map[string]ed25519.PublicKey{"key-requester": reqPub, "key-approver": apprPub},
		RevokedApprovalIDs: map[string]bool{},
	}
	return store, reqPriv, apprPriv
}

func mustSign(t *testing.T, intent domain.ExecutionIntent, priv ed25519.PrivateKey) approval.Document {
	t.Helper()
	hash, err := domain.HashExecutionIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	doc := approval.Document{
		SchemaVersion: approval.SchemaVersion, CanonicalVersion: approval.CanonicalVersion, ApprovalID: "approval-fixture-1",
		IntentHash: hash, RequesterPrincipal: "operator-alice", ApproverPrincipal: "approver-bob",
		Nonce: hex.EncodeToString(nonce), ValidFrom: intent.ValidFrom, ValidUntil: intent.ValidUntil,
		MaintenanceWindow: intent.MaintenanceWindow, Algorithm: approval.AlgorithmEd25519, KeyID: "key-approver",
	}
	signed, err := approval.Sign(priv, doc)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
