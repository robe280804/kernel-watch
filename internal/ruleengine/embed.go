package ruleengine

import _ "embed"

// defaultYAML is the built-in ruleset: the 17 KernelWatch detections plus their
// reusable lists/macros, translated from the original Go rules. It is always
// loaded as the base; operator files (KW_RULES_FILE/KW_RULES_DIR) merge on top.
//
//go:embed default.yaml
var defaultYAML []byte
