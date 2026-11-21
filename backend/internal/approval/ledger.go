package approval

import (
	"encoding/json"
	"os"
	"sync"
)

// Ledger records consumed approval nonces so a valid document cannot be replayed.
type Ledger struct {
	mu   sync.Mutex
	path string
	used map[string]struct{}
}

func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{path: path, used: map[string]struct{}{}}
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, err
	}
	var stored []string
	if err := json.Unmarshal(payload, &stored); err != nil {
		return nil, err
	}
	for _, nonce := range stored {
		l.used[nonce] = struct{}{}
	}
	return l, nil
}

func (l *Ledger) Consume(nonce string) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.used[nonce]; ok {
		return ErrReplay
	}
	l.used[nonce] = struct{}{}
	if l.path == "" {
		return nil
	}
	items := make([]string, 0, len(l.used))
	for nonce := range l.used {
		items = append(items, nonce)
	}
	payload, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return os.WriteFile(l.path, payload, 0o600)
}
