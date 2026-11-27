package execrun

import "github.com/hardw00t/glitchdeck/internal/proxy"

func (e *Envelope) SetAppliedFaults(faults []proxy.AppliedFault) {
	for _, fault := range faults {
		e.FaultsTriggered = append(e.FaultsTriggered, map[string]any{"rule_id": fault.RuleID, "type": fault.Type, "count": fault.Count})
		e.Summary.FaultsTriggered += fault.Count
	}
}
