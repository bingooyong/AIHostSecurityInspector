// Command check-boundaries verifies the offline slice has no process execution
// or network client imports. Future transports must deliberately extend this gate.
package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	forbidden := map[string]bool{"os/exec": true, "plugin": true, "unsafe": true, "net": true, "net/http": true, "golang.org/x/crypto/ssh": true}
	failed := false
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, spec := range file.Imports {
				name, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				if forbidden[name] {
					fmt.Fprintf(os.Stderr, "%s: forbidden offline-slice import %s\n", path, name)
					failed = true
				}
			}
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("PASS: offline slice has no process execution or network client imports")
}
