package execrun

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/ui"
)

var ErrMissingRecordOutput = errors.New("--mode record requires --tape-out")

func (o Options) ValidateMode() error {
	switch o.Mode {
	case "record":
		if o.TapeOut == "" {
			return ErrMissingRecordOutput
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
	doc.Assertions = append([]tape.Assertion(nil), input.Assertions...)
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
	if !doc.Incomplete && !doc.Truncated {
		if _, err := tape.Decode(bytes.NewReader(encoded.Bytes())); err != nil {
			return fmt.Errorf("recorded tape is not replayable: %w", err)
		}
	}
	if o.TapeDestination != nil {
		return o.TapeDestination.Write(encoded.Bytes())
	}
	destination, err := OpenDestination(o.TapeOut)
	if err != nil {
		return err
	}
	defer destination.Close()
	return destination.Write(encoded.Bytes())
}
