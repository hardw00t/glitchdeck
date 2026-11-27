package tlsmitm

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestStoreAndLeaf(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "ca")}
	ca, err := s.Init(false)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := NewMinter(ca, 4, time.Hour).For("localhost")
	if err != nil || len(cert.Certificate) != 2 {
		t.Fatalf("leaf: %v", err)
	}
	if err = os.Chmod(s.Dir+"/ca-key.pem", 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Load(); err == nil {
		t.Fatal("accepted exposed key")
	}
}

func TestRejectInsecureCAStoreDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	store := Store{Dir: filepath.Join(t.TempDir(), "ca")}
	if _, err := store.Init(false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.Dir, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrInsecurePerms) {
		t.Fatalf("load accepted writable CA directory: %v", err)
	}
	if _, err := store.Init(true); !errors.Is(err, ErrInsecurePerms) {
		t.Fatalf("init accepted writable CA directory: %v", err)
	}
}
