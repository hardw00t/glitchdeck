package execrun

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/ui"
)

func (o Options) ValidateMode() error {
	switch o.Mode {
	case "record":
		if o.TapeOut == "" {
			return fmt.Errorf("--mode record requires --tape-out")
		}
		if o.InsecureUpstream {
			return fmt.Errorf("--mode record requires upstream TLS verification")
		}
		return nil
	case "", "passthrough", "replay":
		if o.TapeOut != "" || o.RedactSecrets {
			return fmt.Errorf("--tape-out and --redact-secrets require --mode record")
		}
		return nil
	default:
		return fmt.Errorf("exec mode must be passthrough, record, or replay")
	}
}

func writeRecording(recording *ui.Recording, input tape.Tape, o Options) error {
	doc, err := recording.Export(input.Name)
	if err != nil {
		return err
	}
	if doc.Version < 2 {
		doc.Version = 2
	}
	doc.Expect = input.Expect
	doc.TLSMITM = doc.TLSMITM || o.TLS
	doc.UpstreamAllow = append([]string(nil), input.UpstreamAllow...)
	for _, group := range o.UpstreamAllow {
		for entry := range strings.SplitSeq(group, ",") {
			if !strings.EqualFold(strings.TrimSpace(entry), "any") {
				doc.UpstreamAllow = append(doc.UpstreamAllow, entry)
			}
		}
	}
	doc.TLSPassthrough = append(append([]string(nil), input.TLSPassthrough...), o.TLSPassthrough...)
	if o.RedactSecrets {
		doc, err = tape.PrepareExport(doc, true)
		if err != nil {
			return err
		}
	}
	var encoded bytes.Buffer
	if err := tape.Encode(&encoded, doc); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(o.TapeOut), ".glitchdeck-tape-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(encoded.Bytes())
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), o.TapeOut)
}
