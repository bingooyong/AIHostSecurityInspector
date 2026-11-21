package linux

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const defaultMaxFileBytes int64 = 1 << 20

var errTruncated = errors.New("file exceeds collector byte bound")

type fileView interface {
	ReadFile(name string) ([]byte, error)
	Lstat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	Close() error
}

type osView struct {
	root *os.Root
	max  int64
}

func openView(root string, max int64) (fileView, error) {
	if max <= 0 {
		max = defaultMaxFileBytes
	}
	handle, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	return &osView{root: handle, max: max}, nil
}

func (v *osView) ReadFile(name string) ([]byte, error) {
	file, err := v.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, v.max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > v.max {
		return data[:v.max], errTruncated
	}
	return data, nil
}

func (v *osView) Lstat(name string) (fs.FileInfo, error) {
	return v.root.Lstat(name)
}

func (v *osView) Readlink(name string) (string, error) {
	return v.root.Readlink(name)
}

func (v *osView) ReadDir(name string) ([]fs.DirEntry, error) {
	file, err := v.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return file.ReadDir(0)
}

func (v *osView) Close() error {
	return v.root.Close()
}

func ValidateInspectRoot(root string) error {
	return validateRoot(root)
}

func validateRoot(root string) error {
	if root == "" {
		return errors.New("collector root is required")
	}
	if !filepath.IsAbs(root) {
		return errors.New("collector root must be an absolute path")
	}
	clean := filepath.Clean(root)
	if clean == "/" {
		return errors.New("live root filesystem collection is not enabled")
	}
	if strings.Contains(clean, "\x00") {
		return errors.New("collector root is invalid")
	}
	return nil
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist)
}

func isPermission(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, os.ErrPermission)
}
