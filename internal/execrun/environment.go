package execrun

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hardw00t/glitchdeck/internal/proxy"
)

func mergeNoProxy(upper, lower, explicit, listener string, target *url.URL) (string, []string) {
	seen, kept := map[string]bool{}, []string{}
	var dropped []string
	explicitItems := map[string]string{}
	for raw := range strings.SplitSeq(explicit, ",") {
		key := strings.ToLower(strings.TrimSpace(raw))
		if _, ok := explicitItems[key]; !ok {
			explicitItems[key] = raw
		}
	}
	for i, group := range []string{upper, lower, explicit, listener} {
		for raw := range strings.SplitSeq(group, ",") {
			s := strings.TrimSpace(raw)
			key := strings.ToLower(s)
			if s == "" || seen[key] {
				continue
			}
			explicitRaw, isExplicit := explicitItems[key]
			if i < 2 && !isExplicit && strings.ContainsAny(s, "@?#") {
				seen[key] = true
				dropped = append(dropped, "[redacted]")
				continue
			}
			if i < 2 && !isExplicit && bypassTarget(s, target) {
				seen[key] = true
				dropped = append(dropped, s)
				continue
			}
			seen[key] = true
			if isExplicit {
				s = explicitRaw
			}
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, ","), dropped
}

func bypassTarget(entry string, target *url.URL) bool {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if entry == "*" {
		return true
	}
	if target == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	scoped := false
	if name, scopedPort, err := net.SplitHostPort(entry); err == nil {
		scoped = true
		if strings.TrimLeft(scopedPort, "0") != strings.TrimLeft(port, "0") {
			return false
		}
		entry = name
	}
	entry = strings.TrimSuffix(entry, ".")
	ip := net.ParseIP(host)
	if !scoped && (host == "localhost" || ip.IsLoopback()) {
		switch entry {
		case "localhost", "127.0.0.1", "::1", "[::1]", "127.0.0.0/8":
			return true
		}
	}
	if ip != nil {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			return network.Contains(ip)
		}
		return ip.Equal(net.ParseIP(strings.Trim(entry, "[]")))
	}
	apex := !strings.HasPrefix(entry, "*.")
	domain := strings.TrimPrefix(strings.TrimPrefix(entry, "*."), ".")
	return domain != "" && (apex && host == domain || strings.HasSuffix(host, "."+domain))
}

func reportNoProxy(value string) string {
	if !strings.ContainsAny(value, "@?#") {
		return value
	}
	items := strings.Split(value, ",")
	for i, item := range items {
		if strings.ContainsAny(item, "@?#") {
			items[i] = "[redacted]"
		}
	}
	return strings.Join(items, ",")
}

func inheritedCerts(name string, warn func(string)) []byte {
	path := os.Getenv(name)
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, caReadFlags, 0)
	var data []byte
	if err == nil {
		defer f.Close()
		info, statErr := f.Stat()
		switch {
		case statErr != nil:
			err = statErr
		case !info.Mode().IsRegular():
			err = fmt.Errorf("not a regular file")
		default:
			data, err = io.ReadAll(io.LimitReader(f, 4<<20+1))
			if err == nil && len(data) > 4<<20 {
				err = fmt.Errorf("file exceeds 4 MiB")
			}
		}
	}
	var certs []byte
	if err == nil {
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type == "CERTIFICATE" {
				if _, err := x509.ParseCertificate(block.Bytes); err == nil {
					certs = append(certs, pem.EncodeToMemory(block)...)
				}
			}
		}
		if len(certs) == 0 {
			err = fmt.Errorf("no valid PEM CERTIFICATE blocks")
		}
	}
	if err != nil {
		if warn != nil {
			warn("ca: ignoring unreadable inherited " + name)
			return nil
		}
		if e, ok := err.(*os.PathError); ok {
			err = e.Err
		}
		if strings.ContainsAny(path, "@?#") {
			path = "[redacted]"
		}
		fmt.Fprintf(os.Stderr, "ca: ignoring unreadable inherited %s=%s: %v\n", name, path, err)
		return nil
	}
	return certs
}

func certBundle(parts ...[]byte) []byte {
	var out bytes.Buffer
	seen := map[string]bool{}
	for _, data := range parts {
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type == "CERTIFICATE" && !seen[string(block.Bytes)] {
				if _, err := x509.ParseCertificate(block.Bytes); err != nil {
					continue
				}
				seen[string(block.Bytes)] = true
				_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
			}
		}
	}
	return out.Bytes()
}

func systemPEM() []byte {
	var out []byte
	for _, path := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem"} {
		if data := boundedSystemFile(path); len(data) != 0 {
			return data
		}
	}
	for _, dir := range []string{"/etc/ssl/certs", "/etc/pki/tls/certs"} {
		f, err := os.Open(dir)
		if err != nil {
			continue
		}
		entries, _ := f.ReadDir(4096)
		f.Close()
		for _, entry := range entries {
			if len(out) >= 32<<20 {
				break
			}
			out = append(out, boundedSystemFile(filepath.Join(dir, entry.Name()))...)
		}
	}
	return out
}

func boundedSystemFile(path string) []byte {
	f, err := os.OpenFile(path, caReadFlags, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if err != nil || len(data) > 4<<20 {
		return nil
	}
	var out []byte
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" && block.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		var cert asn1.RawValue
		if _, err := asn1.Unmarshal(block.Bytes, &cert); err != nil {
			continue
		}
		if _, err := x509.ParseCertificate(cert.FullBytes); err != nil {
			continue
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
	return out
}

func proxyRoots(system []byte, inherited ...[]byte) *x509.CertPool {
	var pool *x509.CertPool
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		pool, _ = x509.SystemCertPool()
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(system)
	for _, data := range inherited {
		pool.AppendCertsFromPEM(data)
	}
	return pool
}

func certBundleWithSystem(system []byte, parts ...[]byte) []byte {
	seen := make(map[string]bool)
	for data := system; len(data) > 0; {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		var cert asn1.RawValue
		if _, err := asn1.Unmarshal(block.Bytes, &cert); err == nil {
			seen[string(cert.FullBytes)] = true
		}
	}
	var out bytes.Buffer
	for data := system; len(data) > 0; {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type == "TRUSTED CERTIFICATE" {
			_ = pem.Encode(&out, block)
		} else if block.Type == "CERTIFICATE" && !seen[string(block.Bytes)] {
			if _, err := x509.ParseCertificate(block.Bytes); err == nil {
				seen[string(block.Bytes)] = true
				_ = pem.Encode(&out, block)
			}
		}
	}
	for _, data := range parts {
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type != "CERTIFICATE" || seen[string(block.Bytes)] {
				continue
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				continue
			}
			seen[string(block.Bytes)] = true
			_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
		}
	}
	return out.Bytes()
}

func hint(o Options, cmd []string, target *url.URL, stats proxy.TrafficStats) []string {
	var out []string
	name := ""
	if len(cmd) > 0 {
		name = strings.TrimSuffix(strings.ToLower(filepath.Base(cmd[0])), ".exe")
	}
	zero := stats.RequestsTotal == 0
	rejected := stats.TLSRejected > 0
	if zero && target != nil {
		host := target.Hostname()
		ip := net.ParseIP(host)
		if strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback() {
			out = append(out, "Go net/http (and some other clients) never proxy localhost/127.0.0.1; point the client at $GLITCHDECK_PROXY_URL (reverse mode), use --target, or use 127.0.0.1.nip.io")
		}
	}
	jvm := name == "java" || name == "mvn" || name == "gradle" || name == "gradlew" || name == "kotlin" || name == "sbt" || o.javaHome
	if jvm && rejected {
		out = append(out, "JVM ignores SSL_CERT_FILE; import $GLITCHDECK_CA_CERT with keytool into a PKCS12 truststore and pass -Djavax.net.ssl.trustStore=<file> via JAVA_TOOL_OPTIONS")
	}
	if jvm && zero {
		out = append(out, "JVM ignores HTTP(S)_PROXY; set -Dhttps.proxyHost/-Dhttps.proxyPort via JAVA_TOOL_OPTIONS")
	}
	if name == "dotnet" && rejected {
		out = append(out, ".NET on Linux reads SSL_CERT_FILE/SSL_CERT_DIR via OpenSSL; on macOS/Windows add the CA to the OS store")
	}
	if name == "deno" && zero {
		text := "Deno needs --allow-net and honours HTTPS_PROXY"
		if o.TLS {
			text += "; DENO_CERT is set"
		}
		out = append(out, text)
	}
	return out
}
