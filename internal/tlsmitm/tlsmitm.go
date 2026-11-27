package tlsmitm

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var ErrInsecurePerms = errors.New("CA directory or key has insecure permissions")

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}
type Store struct{ Dir string }

func DefaultDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "glitchdeck", "ca")
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, "glitchdeck", "ca")
}
func (s Store) CertPath() string { return filepath.Join(s.Dir, "ca.pem") }
func serial() (*big.Int, error)  { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func Ephemeral() (*CA, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	sn, e := serial()
	if e != nil {
		return nil, e
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		return nil, e
	}
	skid := sha1.Sum(pub)
	now := time.Now()
	t := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "glitchdeck local CA " + sn.Text(16), Organization: []string{"glitchdeck"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: skid[:]}
	der, e := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, e
	}
	return &CA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}
func (c *CA) Fingerprint() string { v := sha256.Sum256(c.Cert.Raw); return hex.EncodeToString(v[:]) }
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".ca-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	if x := f.Close(); e == nil {
		e = x
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}
func (s Store) Init(force bool) (*CA, error) {
	if e := os.MkdirAll(s.Dir, 0700); e != nil {
		return nil, e
	}
	if e := s.checkDir(); e != nil {
		return nil, e
	}
	if !force {
		if _, e := os.Stat(s.CertPath()); e == nil {
			return nil, os.ErrExist
		}
		if _, e := os.Stat(filepath.Join(s.Dir, "ca-key.pem")); e == nil {
			return nil, os.ErrExist
		}
	}
	c, e := Ephemeral()
	if e != nil {
		return nil, e
	}
	key, e := x509.MarshalPKCS8PrivateKey(c.Key)
	if e != nil {
		return nil, e
	}
	if e = atomicWrite(filepath.Join(s.Dir, "ca-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); e != nil {
		return nil, e
	}
	if e = atomicWrite(s.CertPath(), c.PEM, 0644); e != nil {
		return nil, e
	}
	return c, nil
}
func (s Store) Load() (*CA, error) {
	if e := s.checkDir(); e != nil {
		return nil, e
	}
	path := filepath.Join(s.Dir, "ca-key.pem")
	st, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("CA key must be a regular file")
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		return nil, ErrInsecurePerms
	}
	k, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(k)
	if block == nil {
		return nil, errors.New("invalid CA key")
	}
	v, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	key, ok := v.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid CA key")
	}
	certPEM, e := os.ReadFile(s.CertPath())
	if e != nil {
		return nil, e
	}
	block, _ = pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("invalid CA certificate")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, e
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !cert.IsCA || !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("CA key mismatch")
	}
	return &CA{cert, key, certPEM}, nil
}

func (s Store) checkDir() error {
	info, err := os.Stat(s.Dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return ErrInsecurePerms
	}
	return nil
}

type cacheEntry struct {
	host string
	cert *tls.Certificate
	at   time.Time
}
type Minter struct {
	ca      *CA
	key     *ecdsa.PrivateKey
	size    int
	ttl     time.Duration
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
}

func NewMinter(ca *CA, size int, ttl time.Duration) *Minter {
	if size <= 0 {
		size = 1024
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &Minter{ca: ca, key: key, size: size, ttl: ttl, entries: map[string]*list.Element{}, lru: list.New()}
}
func (m *Minter) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.For(h.ServerName)
}
func (m *Minter) For(host string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil || host == "" {
		return nil, errors.New("invalid leaf host")
	}
	if e := m.entries[host]; e != nil {
		v := e.Value.(cacheEntry)
		if time.Since(v.at) < m.ttl {
			m.lru.MoveToFront(e)
			return v.cert, nil
		}
		m.lru.Remove(e)
		delete(m.entries, host)
	}
	sn, e := serial()
	if e != nil {
		return nil, e
	}
	now := time.Now()
	t := &x509.Certificate{SerialNumber: sn, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, AuthorityKeyId: m.ca.Cert.SubjectKeyId}
	if ip := net.ParseIP(host); ip != nil {
		t.IPAddresses = []net.IP{ip}
	} else {
		t.DNSNames = []string{host}
		if host == "localhost" {
			t.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, t, m.ca.Cert, &m.key.PublicKey, m.ca.Key)
	if e != nil {
		return nil, e
	}
	c := &tls.Certificate{Certificate: [][]byte{der, m.ca.Cert.Raw}, PrivateKey: m.key}
	el := m.lru.PushFront(cacheEntry{host, c, now})
	m.entries[host] = el
	if m.lru.Len() > m.size {
		old := m.lru.Back()
		delete(m.entries, old.Value.(cacheEntry).host)
		m.lru.Remove(old)
	}
	return c, nil
}
