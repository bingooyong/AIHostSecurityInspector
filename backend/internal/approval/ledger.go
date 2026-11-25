package approval

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
)

const maxLedgerBytes = 1 << 20

// Ledger records consumed approval nonces and authorized-collection intent hashes.
// Persistent ledgers require a trusted private local directory and a stable path.
// The .lock sidecar must never be removed or replaced while consumers may run.
type Ledger struct {
	mu       sync.Mutex
	path     string
	used     map[string]struct{} // Used only by an explicitly in-memory ledger.
	observed bool
}

func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{used: map[string]struct{}{}}
	if path == "" {
		return l, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("invalid ledger path")
	}
	l.path = absolute
	_, exists, err := readLedger(l.path)
	if err != nil {
		return nil, err
	}
	l.observed = exists
	return l, nil
}

func (l *Ledger) Consume(nonce string) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path == "" {
		if _, ok := l.used[nonce]; ok {
			return ErrReplay
		}
		l.used[nonce] = struct{}{}
		return nil
	}
	// Lock a stable inode, not the JSON file which atomic replacement changes.
	lock, err := openLedgerFile(l.path+".lock", os.O_RDWR|os.O_CREATE)
	if err != nil {
		return errors.New("cannot open ledger lock")
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("cannot lock ledger; another consumer may be active")
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	used, exists, err := readLedger(l.path)
	if err != nil {
		return err
	}
	if !exists && l.observed {
		return errors.New("ledger state disappeared")
	}
	l.observed = exists
	if _, ok := used[nonce]; ok {
		return ErrReplay
	}
	used[nonce] = struct{}{}
	items := make([]string, 0, len(used))
	for value := range used {
		items = append(items, value)
	}
	sort.Strings(items)
	payload, err := json.Marshal(items)
	if err != nil || len(payload) > maxLedgerBytes {
		return errors.New("ledger capacity exceeded")
	}
	if err := l.persist(payload); err != nil {
		return err
	}
	return nil
}

func openLedgerFile(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, errors.New("cannot inspect ledger file")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 || !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		_ = f.Close()
		return nil, errors.New("ledger requires a private owned regular single-link file")
	}
	return f, nil
}

func readLedger(path string) (map[string]struct{}, bool, error) {
	used := map[string]struct{}{}
	f, err := openLedgerFile(path, os.O_RDONLY)
	if err != nil {
		if os.IsNotExist(err) {
			return used, false, nil
		}
		return nil, false, errors.New("cannot open ledger state")
	}
	defer func() { _ = f.Close() }()
	payload, err := io.ReadAll(io.LimitReader(f, maxLedgerBytes+1))
	if err != nil || len(payload) > maxLedgerBytes {
		return nil, true, errors.New("cannot read bounded ledger state")
	}
	var stored []string
	if err := json.Unmarshal(payload, &stored); err != nil || stored == nil {
		return nil, true, errors.New("ledger state is corrupt")
	}
	for _, nonce := range stored {
		used[nonce] = struct{}{}
	}
	return used, true, nil
}

func (l *Ledger) persist(payload []byte) error {
	dir, err := os.Open(filepath.Dir(l.path))
	if err != nil {
		return errors.New("cannot open ledger directory")
	}
	defer func() { _ = dir.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(l.path), ".hostsec-ledger-*")
	if err != nil {
		return errors.New("cannot create ledger snapshot")
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(payload); err != nil {
		return errors.New("cannot write ledger snapshot")
	}
	if err := tmp.Sync(); err != nil {
		return errors.New("cannot sync ledger snapshot")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("cannot close ledger snapshot")
	}
	if err := os.Rename(tmp.Name(), l.path); err != nil {
		return errors.New("cannot commit ledger snapshot")
	}
	// A later sync failure is an indeterminate commit, never a grant to execute.
	l.observed = true
	if err := dir.Sync(); err != nil {
		return errors.New("cannot sync ledger directory; nonce may already be consumed")
	}
	return nil
}
