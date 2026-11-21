package runner

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/orchestrator"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/sign"
)

var (
	ErrZone    = errors.New("runner zone does not match task or host")
	ErrReplay  = errors.New("task nonce already consumed")
	ErrExpired = errors.New("task has expired")
	ErrSign    = errors.New("task signature is invalid")
)

type Task struct {
	TaskID    string `json:"task_id"`
	Zone      string `json:"zone"`
	HostID    string `json:"host_id"`
	Profile   string `json:"profile"`
	ScanID    string `json:"scan_id"`
	Root      string `json:"fixture_root"`
	OutDir    string `json:"out_dir"`
	Expires   string `json:"expires"`
	Nonce     string `json:"nonce"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature,omitempty"`
}

type unsignedTask struct {
	TaskID  string `json:"task_id"`
	Zone    string `json:"zone"`
	HostID  string `json:"host_id"`
	Profile string `json:"profile"`
	ScanID  string `json:"scan_id"`
	Root    string `json:"fixture_root"`
	OutDir  string `json:"out_dir"`
	Expires string `json:"expires"`
	Nonce   string `json:"nonce"`
	KeyID   string `json:"key_id"`
}

type Runner struct {
	Zone      string
	Inventory asset.Inventory
	Caller    authorization.Principal
	Keys      map[string]ed25519.PublicKey
	Now       func() time.Time
	mu        sync.Mutex
	used      map[string]struct{}
}

func (t Task) Canonical() ([]byte, error) {
	return sign.Canonical(unsignedTask{
		TaskID: t.TaskID, Zone: t.Zone, HostID: t.HostID, Profile: t.Profile, ScanID: t.ScanID,
		Root: t.Root, OutDir: t.OutDir, Expires: t.Expires, Nonce: t.Nonce, KeyID: t.KeyID,
	})
}

func SignTask(private ed25519.PrivateKey, task Task) (Task, error) {
	canonical, err := task.Canonical()
	if err != nil {
		return Task{}, err
	}
	sig, err := sign.Sign(private, canonical)
	if err != nil {
		return Task{}, err
	}
	task.Signature = sig
	return task, nil
}

func (r *Runner) Execute(ctx context.Context, task Task) (orchestrator.Result, error) {
	out := orchestrator.Result{CollectorAvailable: false, ScanReady: false, ExecutionReady: false, Limitations: []string{"in-process local runner; mTLS is unverified", "SSH transport was not used"}}
	if r.used == nil {
		r.used = map[string]struct{}{}
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if task.Zone != r.Zone {
		return out, ErrZone
	}
	expires, err := domain.ParseUTC(task.Expires)
	if err != nil || !r.Now().Before(expires) {
		return out, ErrExpired
	}
	pub, ok := r.Keys[task.KeyID]
	if !ok {
		return out, ErrSign
	}
	canonical, err := task.Canonical()
	if err != nil {
		return out, err
	}
	if err := sign.Verify(pub, canonical, task.Signature); err != nil {
		return out, ErrSign
	}
	r.mu.Lock()
	if _, ok := r.used[task.Nonce]; ok {
		r.mu.Unlock()
		return out, ErrReplay
	}
	r.used[task.Nonce] = struct{}{}
	r.mu.Unlock()
	var host asset.Host
	for _, item := range r.Inventory.Hosts {
		if item.ID == task.HostID {
			host = item
			break
		}
	}
	if host.ID == "" || host.Zone != r.Zone {
		return out, ErrZone
	}
	if err := r.Caller.AllowsHost(host); err != nil {
		return out, err
	}
	result, err := orchestrator.InspectFixture(ctx, orchestrator.Request{
		Root: task.Root, Inventory: r.Inventory, HostID: task.HostID, Profile: task.Profile,
		OutDir: task.OutDir, ScanID: task.ScanID, Now: r.Now,
	})
	if err != nil {
		return result, err
	}
	result.Limitations = append(result.Limitations, "in-process local runner; mTLS is unverified")
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		return result, errors.New("runner must not mark live scan ready")
	}
	return result, nil
}
