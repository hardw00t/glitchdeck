package execrun

import "github.com/hardw00t/glitchdeck/internal/proxy"

func (e *Envelope) SetAppliedFaults(faults []proxy.AppliedFault) {
	for _, fault := range faults {
		entry := map[string]any{"rule_id": fault.RuleID, "type": fault.Type, "count": fault.Count}
		if fault.Replays != nil {
			entry["replays"] = fault.Replays
		}
		if len(fault.SkipReasons) != 0 {
			entry["skip_reasons"] = fault.SkipReasons
		}
		e.FaultsTriggered = append(e.FaultsTriggered, entry)
		e.Summary.FaultsTriggered += fault.Count
	}
}
