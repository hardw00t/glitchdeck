package execrun

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func WriteReport(path string, report Envelope) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".glitchdeck-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	encodeErr := json.NewEncoder(file).Encode(report)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}

func (d *Destination) WriteReport(report Envelope) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return d.Write(append(data, '\n'))
}
