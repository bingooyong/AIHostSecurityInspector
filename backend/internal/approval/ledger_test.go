package approval

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLedgerRejectsReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.json")
	ledger, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("abc"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("abc"); err != ErrReplay {
		t.Fatalf("replay accepted: %v", err)
	}
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Consume("abc"); err != ErrReplay {
		t.Fatal("replay survived process restart")
	}
}

func TestLedgerIndependentHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.json")
	first, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Consume("first"); err != nil {
		t.Fatal(err)
	}
	if err := second.Consume("first"); err != ErrReplay {
		t.Fatalf("stale handle accepted replay: %v", err)
	}
	if err := second.Consume("second"); err != nil {
		t.Fatal(err)
	}
	if err := first.Consume("third"); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []string{"first", "second", "third"} {
		if err := reopened.Consume(nonce); err != ErrReplay {
			t.Errorf("lost nonce %q: %v", nonce, err)
		}
	}
}

func TestLedgerFailedWriteDoesNotConsume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "nonces.json")
	ledger, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("retry"); err == nil {
		t.Fatal("write unexpectedly succeeded")
	}
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("retry"); err != nil {
		t.Fatalf("failed write poisoned nonce: %v", err)
	}
}

func TestLedgerRejectsChangedState(t *testing.T) {
	for _, change := range []string{"missing", "corrupt", "null"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nonces.json")
			ledger, err := OpenLedger(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.Consume("first"); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "missing":
				err = os.Remove(path)
			case "corrupt":
				err = os.WriteFile(path, []byte("["), 0o600)
			case "null":
				err = os.WriteFile(path, []byte("null"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.Consume("second"); err == nil {
				t.Fatal("changed state silently replaced")
			}
		})
	}
}

func TestLedgerRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public", "null", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "nonces.json")
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("[]"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(target, path)
			case "public":
				err = os.WriteFile(path, []byte("[]"), 0o644)
			case "null":
				err = os.WriteFile(path, []byte("null"), 0o600)
			case "oversized":
				err = os.WriteFile(path, []byte("["+strings.Repeat(" ", 1<<20)+"]"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenLedger(path); err == nil {
				t.Fatal("unsafe ledger accepted")
			}
		})
	}
}

func TestLedgerLockFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.json")
	ledger, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("blocked"); err == nil {
		t.Error("busy lock ignored")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("blocked"); err != nil {
		t.Fatalf("lock failure consumed nonce: %v", err)
	}
}

// Each child opens before the parent releases any consumer. These are actual
// separate processes; goroutine race coverage alone cannot prove file locking.
func TestLedgerProcessContention(t *testing.T) {
	if path := os.Getenv("HOSTSEC_TEST_LEDGER_PATH"); path != "" {
		ledger, err := OpenLedger(path)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("ready")
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		err = ledger.Consume("shared")
		switch {
		case err == nil:
			fmt.Println("accepted")
		case err == ErrReplay || strings.Contains(err.Error(), "lock"):
			fmt.Println("rejected")
		default:
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "nonces.json")
	type child struct {
		cmd     *exec.Cmd
		release func()
		output  *bufio.Reader
	}
	children := make([]child, 0, 4)
	for range 4 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerProcessContention$", "-test.timeout=15s")
		cmd.Env = append(os.Environ(), "HOSTSEC_TEST_LEDGER_PATH="+path)
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		reader := bufio.NewReader(output)
		if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
			t.Fatalf("child not ready: %q %v", line, err)
		}
		children = append(children, child{cmd, func() { _, _ = fmt.Fprintln(input); _ = input.Close() }, reader})
	}
	for _, c := range children {
		c.release()
	}
	accepted := 0
	for _, c := range children {
		line, err := c.output.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "accepted\n" {
			accepted++
		} else if line != "rejected\n" {
			t.Fatalf("unexpected child result %q", line)
		}
		if err := c.cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("expected exactly one consumer, got %d", accepted)
	}
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Consume("shared"); err != ErrReplay {
		t.Fatalf("process result not durable: %v", err)
	}
}

func TestLedgerFailedSnapshotPreservesHistory(t *testing.T) {
	if path := os.Getenv("HOSTSEC_TEST_LEDGER_WRITE_FAILURE"); path != "" {
		ledger, err := OpenLedger(path)
		if err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var original syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
			t.Fatal(err)
		}
		signal.Ignore(syscall.SIGXFSZ)
		limited := original
		limited.Cur = 1
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
			t.Fatal(err)
		}
		writeErr := ledger.Consume("new")
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
			t.Fatal(err)
		}
		if writeErr == nil {
			t.Fatal("limited snapshot write succeeded")
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("failed snapshot damaged consumed history")
		}
		if err := ledger.Consume("new"); err != nil {
			t.Fatalf("failed snapshot poisoned retry: %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "nonces.json")
	if err := os.WriteFile(path, []byte(`["persisted"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerFailedSnapshotPreservesHistory$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "HOSTSEC_TEST_LEDGER_WRITE_FAILURE="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("snapshot failure child: %v %s", err, out)
	}
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []string{"persisted", "new"} {
		if err := reopened.Consume(nonce); err != ErrReplay {
			t.Fatalf("history lost: %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".hostsec-ledger-") {
			t.Fatal("failed snapshot was not cleaned up")
		}
	}
}

func TestLedgerRejectsUnsafeLockAndFIFO(t *testing.T) {
	for _, kind := range []string{"symlink-lock", "fifo-lock", "public-lock", "fifo-state"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nonces.json")
			ledger, err := OpenLedger(path)
			if err != nil {
				t.Fatal(err)
			}
			target := path + ".lock"
			switch kind {
			case "symlink-lock":
				err = os.Symlink(path+".absent", target)
			case "fifo-lock":
				err = syscall.Mkfifo(target, 0o600)
			case "public-lock":
				err = os.WriteFile(target, []byte(""), 0o644)
			case "fifo-state":
				err = syscall.Mkfifo(path, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.Consume("unsafe"); err == nil {
				t.Fatal("unsafe state or lock accepted")
			}
			if kind == "fifo-state" {
				if _, err := OpenLedger(path); err == nil {
					t.Fatal("FIFO opened as ledger")
				}
			}
		})
	}
}
