package alerter

import "strings"

// ECS maps an Alert onto the Elastic Common Schema (ECS) so KernelWatch output
// drops straight into Elasticsearch / Kibana / Elastic Security and any SIEM
// that speaks ECS — selected with KW_ALERT_FORMAT=ecs.
//
// Only stable, widely-indexed ECS fields are populated; KernelWatch-specific
// extras that have no ECS home live under the custom `kernelwatch.*` namespace,
// which is the ECS-sanctioned way to carry vendor fields.
//
// Reference: https://www.elastic.co/guide/en/ecs/current/index.html
func (a *Alert) ECS() map[string]any {
	m := map[string]any{
		"@timestamp": a.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		"message":    a.Reason,
		"ecs":        map[string]any{"version": "8.11.0"},
		"event": map[string]any{
			"kind":     "alert",
			"category": []string{"intrusion_detection"},
			"type":     []string{ecsEventType(a)},
			"severity": ecsSeverity(a.Severity),
			"action":   a.RuleID,
			"reason":   a.Reason,
			"module":   "kernelwatch",
			"provider": "ebpf",
		},
		"host":     map[string]any{"name": a.ServerName},
		"observer": map[string]any{"product": "KernelWatch", "type": "hids", "vendor": "KernelWatch"},
	}

	// Container.
	container := map[string]any{}
	if a.ContainerID != "" {
		container["id"] = a.ContainerID
	}
	if a.ContainerName != "" {
		container["name"] = a.ContainerName
	}
	if a.ImageName != "" {
		container["image"] = map[string]any{"name": a.ImageName}
	}
	if len(container) > 0 {
		m["container"] = container
	}

	// Process + lineage.
	process := map[string]any{}
	if a.PID != 0 {
		process["pid"] = a.PID
	}
	if a.ProcessName != "" {
		process["name"] = a.ProcessName
	}
	if a.CmdLine != "" {
		process["command_line"] = a.CmdLine
	}
	if a.ParentName != "" {
		process["parent"] = map[string]any{"name": a.ParentName}
	}
	if len(process) > 0 {
		m["process"] = process
	}

	// MITRE ATT&CK → ECS threat fields.
	if a.MITRETTP != "" || a.MITRETactic != "" {
		threat := map[string]any{"framework": "MITRE ATT&CK"}
		if a.MITRETactic != "" {
			threat["tactic"] = map[string]any{"name": a.MITRETactic}
		}
		if a.MITRETTP != "" {
			threat["technique"] = map[string]any{"id": a.MITRETTP}
		}
		m["threat"] = threat
	}

	if len(a.Tags) > 0 {
		m["tags"] = a.Tags
	}

	// Vendor namespace for fields ECS does not model.
	kw := map[string]any{"rule_id": a.RuleID}
	kw["scope"] = a.scopeOrDefault()
	if a.Syscall != "" {
		kw["syscall"] = a.Syscall
	}
	if len(a.Ancestry) > 0 {
		kw["ancestry"] = a.Ancestry
	}
	if phase := a.KillChainPhase; phase != "" {
		kw["kill_chain_phase"] = phase
	}
	if a.RiskScore > 0 {
		kw["risk_score"] = a.RiskScore
	}
	if len(a.Details) > 0 {
		kw["details"] = a.Details
	}
	m["kernelwatch"] = kw

	return m
}

// ecsSeverity maps the four KernelWatch severities onto ECS event.severity, an
// integer where higher means more severe (kept within a stable 0–100 band).
func ecsSeverity(s Severity) int {
	switch s {
	case SeverityCritical:
		return 99
	case SeverityHigh:
		return 73
	case SeverityMedium:
		return 47
	case SeverityLow:
		return 21
	default:
		return 0
	}
}

// ecsEventType picks the closest ECS event.type for an alert. Correlated
// incidents are "indicator"; file opens are "access"; everything else maps to
// the process-execution-centric "start".
func ecsEventType(a *Alert) string {
	if a.IsIncident() {
		return "indicator"
	}
	switch strings.ToLower(a.Syscall) {
	case "open", "openat":
		return "access"
	case "connect":
		return "connection"
	default:
		return "start"
	}
}
