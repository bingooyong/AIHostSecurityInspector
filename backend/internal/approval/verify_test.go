package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
)

func fixtureIntent(t *testing.T, profile string) domain.ExecutionIntent {
	t.Helper()
	inv, err := asset.Load(context.Background(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Get(profile)
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
		SchemaVersion:      domain.IntentSchemaVersion,
		CanonicalVersion:   domain.IntentCanonicalVersion,
		RequesterPrincipal: "operator-alice",
		HostIDs:            []string{"linux-test-001"},
		IdentityRefs:       []string{"hostid-linux-test-001"},
		AssetSnapshotHash:  snap,
		PolicyID:           policy.PolicyID,
		PolicyVersion:      policy.PolicyVersion,
		PolicyHash:         policyHash,
		Profile:            p.Name,
		Modules:            p.Modules,
		Tools:              p.Tools,
		AllowedPaths:       p.Limits.AllowedPaths,
		ExcludedPaths:      p.Limits.ExcludedPaths,
		ExcludedMountTypes: p.Limits.ExcludedMountTypes,
		Limits: domain.IntentLimits{
			TimeoutSeconds: p.Limits.TimeoutSeconds, MaxConcurrency: p.Limits.MaxConcurrency,
			MaxFiles: p.Limits.MaxFiles, MaxFileSizeBytes: p.Limits.MaxFileSizeBytes,
			IOMaxBytesPerSecond: p.Limits.IOMaxBytesPerSecond, StopOnResourcePressure: true,
			MaintenanceWindowRequired: p.Limits.MaintenanceWindowRequired,
		},
		RequiredCapabilities: []string{"linux_proc"},
		ValidFrom:            "2026-11-20T00:00:00Z",
		ValidUntil:           "2026-11-20T06:00:00Z",
		Mode:                 domain.ModeReadOnly,
	}
	if p.Limits.MaintenanceWindowRequired {
		intent.MaintenanceWindow = &domain.MaintenanceWindow{Timezone: "UTC", Start: "2026-11-20T01:00:00Z", End: "2026-11-20T03:00:00Z"}
	}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	return intent
}

func testStore(t *testing.T) (TrustStore, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	reqPub, reqPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	apprPub, apprPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := TrustStore{
		Principals: map[string]Principal{
			"operator-alice": {ID: "operator-alice", KeyID: "key-requester", CanRequest: true},
			"approver-bob":   {ID: "approver-bob", KeyID: "key-approver", CanApprove: true},
		},
		Keys: map[string]ed25519.PublicKey{
			"key-requester": reqPub,
			"key-approver":  apprPub,
		},
		RevokedApprovalIDs: map[string]bool{},
	}
	return store, reqPriv, apprPriv
}

func signedDoc(t *testing.T, intent domain.ExecutionIntent, priv ed25519.PrivateKey) Document {
	t.Helper()
	hash, err := domain.HashExecutionIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	doc := Document{
		SchemaVersion: SchemaVersion, CanonicalVersion: CanonicalVersion, ApprovalID: "approval-fixture-1",
		IntentHash: hash, RequesterPrincipal: "operator-alice", ApproverPrincipal: "approver-bob",
		Nonce: hex.EncodeToString(nonce), ValidFrom: intent.ValidFrom, ValidUntil: intent.ValidUntil,
		MaintenanceWindow: intent.MaintenanceWindow, Algorithm: AlgorithmEd25519, KeyID: "key-approver",
	}
	signed, err := Sign(priv, doc)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestVerifyAcceptsIndependentApprover(t *testing.T) {
	intent := fixtureIntent(t, domain.ProfileDeep)
	store, _, approver := testStore(t)
	doc := signedDoc(t, intent, approver)
	now := time.Date(2026, 11, 20, 1, 30, 0, 0, time.UTC)
	if _, err := Verify(store, doc, intent, now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsForgeryExpiryReplayAndSelfApproval(t *testing.T) {
	intent := fixtureIntent(t, domain.ProfileDeep)
	store, requester, approver := testStore(t)
	now := time.Date(2026, 11, 20, 1, 30, 0, 0, time.UTC)
	t.Run("wrong key", func(t *testing.T) {
		doc := signedDoc(t, intent, requester)
		doc.KeyID = "key-approver"
		if _, err := Verify(store, doc, intent, now); err == nil {
			t.Fatal("requester signature accepted as approver")
		}
	})
	t.Run("expired", func(t *testing.T) {
		doc := signedDoc(t, intent, approver)
		if _, err := Verify(store, doc, intent, time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)); err != ErrExpired {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("future", func(t *testing.T) {
		doc := signedDoc(t, intent, approver)
		if _, err := Verify(store, doc, intent, time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)); err != ErrNotYetValid {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("intent drift", func(t *testing.T) {
		doc := signedDoc(t, intent, approver)
		changed := intent
		changed.Limits.MaxFiles = 1
		if _, err := Verify(store, doc, changed, now); err != ErrIntentMismatch {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("self approve", func(t *testing.T) {
		doc := signedDoc(t, intent, approver)
		doc.ApproverPrincipal = "operator-alice"
		signed, err := Sign(approver, doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(store, signed, intent, now); err == nil {
			t.Fatal("same-person approval accepted")
		}
	})
	t.Run("revoked", func(t *testing.T) {
		doc := signedDoc(t, intent, approver)
		store.RevokedApprovalIDs[doc.ApprovalID] = true
		if _, err := Verify(store, doc, intent, now); err != ErrRevoked {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("approval-id is not authorization", func(t *testing.T) {
		doc := signedDoc(t, intent, approver)
		doc.Signature = ""
		if _, err := Verify(store, doc, intent, now); err == nil {
			t.Fatal("unsigned approval-id accepted")
		}
	})
}
