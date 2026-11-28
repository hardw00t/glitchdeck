package execrun

import (
	"encoding/json"
)

func WriteReport(path string, report Envelope) error {
	destination, err := OpenDestination(path)
	if err != nil {
		return err
	}
	defer destination.Close()
	return destination.WriteReport(report)
}

func (d *Destination) WriteReport(report Envelope) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return d.Write(append(data, '\n'))
}
