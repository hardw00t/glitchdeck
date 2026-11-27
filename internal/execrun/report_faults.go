package execrun

import "github.com/hardw00t/glitchdeck/internal/proxy"

func (e *Envelope) SetAppliedFaults(faults []proxy.AppliedFault) {
	for _, fault := range faults {
		entry := map[string]any{"rule_id": fault.RuleID, "type": fault.Type, "count": fault.Count}
		if fault.Replays != nil {
			entry["replays"] = fault.Replays
		}
		if fault.Type == "dup-webhook" && fault.SkipReasons["replay_capacity_exceeded"] != 0 {
			entry["skip_reasons"] = map[string]uint64{"replay_capacity_exceeded": fault.SkipReasons["replay_capacity_exceeded"]}
		}
		e.FaultsTriggered = append(e.FaultsTriggered, entry)
		e.Summary.FaultsTriggered += fault.Count
	}
}
