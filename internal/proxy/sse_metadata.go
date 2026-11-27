package proxy

import (
	"net/http"
	"strings"
)

func stripSSEIntegrity(h http.Header) {
	for _, name := range [...]string{"Content-Digest", "Repr-Digest", "Digest", "Content-Md5", "Signature", "Signature-Input"} {
		h.Del(name)
	}
	if !strings.HasPrefix(h.Get("ETag"), "W/") {
		h.Del("ETag")
	}
}
