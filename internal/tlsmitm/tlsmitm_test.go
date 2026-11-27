package tlsmitm

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
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

func TestLoadReturnsOnlyCertificate(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "ca")}
	ca, err := store.Init(false)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(store.Dir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.CertPath(), append(bytes.Clone(ca.PEM), key...), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	block, tail := pem.Decode(loaded.PEM)
	if block == nil || block.Type != "CERTIFICATE" || len(tail) != 0 || !bytes.Equal(block.Bytes, ca.Cert.Raw) {
		t.Fatal("public PEM contains material other than the CA certificate")
	}
}

func TestLeafValidityStaysWithinIssuerValidity(t *testing.T) {
	ca, err := Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	ca.Cert.NotAfter = time.Now().Add(time.Hour).Truncate(time.Second)
	minter := NewMinter(ca, 1, time.Hour)
	leaf, err := minter.For("localhost")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil || !cert.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Fatalf("leaf validity not bounded by issuer: %v", err)
	}
	ca.Cert.NotAfter = time.Now().Add(-time.Second)
	if _, err := minter.For("localhost"); err == nil {
		t.Fatal("returned cached leaf for an expired issuer")
	}
}
