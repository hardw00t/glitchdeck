package execrun

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Destination retains the supplied parent directory across child execution.
type Destination struct {
	root *os.Root
	name string
}

func OpenDestination(path string) (*Destination, error) {
	parent, name := filepath.Split(path)
	if parent == "" {
		parent = "."
	}
	if name == "" || name == "." || name == ".." || !filepath.IsLocal(name) {
		return nil, fs.ErrInvalid
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	return &Destination{root: root, name: name}, nil
}

func (d *Destination) Close() error { return d.root.Close() }

func (d *Destination) Same(other *Destination, input ...os.FileInfo) (bool, error) {
	a, err := d.root.Stat(".")
	if err != nil {
		return false, err
	}
	b, err := other.root.Stat(".")
	if err != nil {
		return false, err
	}
	if os.SameFile(a, b) && (d.name == other.name || (runtime.GOOS == "windows" || runtime.GOOS == "darwin") && strings.EqualFold(d.name, other.name)) {
		return true, nil
	}
	a, err = d.root.Stat(d.name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if a == nil {
		return false, nil
	}
	if len(input) != 0 && input[0] != nil && os.SameFile(a, input[0]) {
		return true, nil
	}
	b, err = other.root.Stat(other.name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Resolve escaping links relative to the pinned parent on Linux.
		if link, linkErr := other.root.Readlink(other.name); linkErr == nil {
			if filepath.IsAbs(link) {
				b, err = os.Stat(link)
			} else if runtime.GOOS == "linux" {
				parent, openErr := other.root.Open(".")
				if openErr == nil {
					b, err = os.Stat("/proc/self/fd/" + fmt.Sprint(parent.Fd()) + "/" + link)
					parent.Close()
				}
			} else {
				pinned, pinErr := other.root.Stat(".")
				before, beforeErr := os.Stat(other.root.Name())
				if pinErr == nil && beforeErr == nil && os.SameFile(pinned, before) {
					b, err = os.Stat(other.root.Name() + string(os.PathSeparator) + link)
					after, afterErr := os.Stat(other.root.Name())
					if afterErr != nil || !os.SameFile(pinned, after) {
						b, err = nil, fs.ErrInvalid
					}
				} else {
					b, err = nil, fs.ErrInvalid
				}
			}
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	return a != nil && b != nil && os.SameFile(a, b), nil
}

func (d *Destination) Write(data []byte) error {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	name := ".glitchdeck-" + hex.EncodeToString(token[:])
	file, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer d.root.Remove(name)
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return d.root.Rename(name, d.name)
}
