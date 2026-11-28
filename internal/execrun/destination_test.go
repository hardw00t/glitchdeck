package execrun

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDestinationPinsParentAndPreservesSymlinkDotDot(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"actual/child", "other"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "actual/child"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDestination(filepath.Join(dir, "link") + "/../result")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := os.Rename(filepath.Join(dir, "actual"), filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "other"), filepath.Join(dir, "actual")); err != nil {
		t.Fatal(err)
	}
	if err := d.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "moved/result"))
	if err != nil || string(got) != "safe" {
		t.Fatalf("pinned output: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "actual/result")); !os.IsNotExist(err) {
		t.Fatalf("replacement directory modified: %v", err)
	}
}

func TestDestinationDetectsAliases(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "real/child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real/child"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	a, err := OpenDestination(filepath.Join(dir, "link") + "/../out")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenDestination(filepath.Join(dir, "real/out"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	same, err := a.Same(b)
	if err != nil || !same {
		t.Fatalf("alias not detected: %v %v", same, err)
	}
}
