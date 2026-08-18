package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleGetSystemConfig(client *truenas.Client, args map[string]interface{}) (string, error) {
	result, err := client.Call("system.general.config")
	if err != nil {
		return "", err
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(result, &cfg); err != nil {
		return "", fmt.Errorf("failed to parse system config: %w", err)
	}

	// Redact any credential-bearing fields.
	safe := redactSystemConfig(cfg)

	formatted, err := json.MarshalIndent(safe, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleUpdateSystemConfig(client *truenas.Client, args map[string]interface{}) (string, error) {
	payload := map[string]interface{}{}
	stringFields := []string{"timezone", "language", "hostname", "domain", "http_proxy", "https_proxy"}
	for _, f := range stringFields {
		if v, ok := args[f].(string); ok && v != "" {
			payload[f] = v
		}
	}

	if gateway, ok := args["gateway"].(string); ok && gateway != "" {
		payload["gateway"] = gateway
	}
	if nameservers, ok := args["nameserver1"].(string); ok && nameservers != "" {
		payload["nameserver1"] = nameservers
	}
	if ns2, ok := args["nameserver2"].(string); ok && ns2 != "" {
		payload["nameserver2"] = ns2
	}
	if ds, ok := args["directory_service"].(map[string]interface{}); ok {
		payload["directory_service"] = ds
	}

	if len(payload) == 0 {
		return "", fmt.Errorf("no fields to update (timezone, language, hostname, domain, gateway, nameserver1, nameserver2, http_proxy, https_proxy)")
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "system.general.update",
			"payload":   payload,
			"note":      "Preview only. No config updated.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("system.general.update", payload)
	if err != nil {
		return "", fmt.Errorf("failed to update system config: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"updated_fields": payload,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// redactSystemConfig masks any credential-bearing fields in the system config.
func redactSystemConfig(cfg map[string]interface{}) map[string]interface{} {
	safe := make(map[string]interface{}, len(cfg))
	for k, v := range cfg {
		if k == "ds_auth" || k == "directory_service" {
			if vm, ok := v.(map[string]interface{}); ok {
				safe[k] = redactSystemConfig(vm)
				continue
			}
		}
		// Use the existing isSensitiveKey from the truenas package logic.
		if isSensitiveKeyPublic(k) {
			safe[k] = "[REDACTED]"
		} else {
			safe[k] = v
		}
	}
	return safe
}

// isSensitiveKeyPublic mirrors truenas.isSensitiveKey but is exported here
// since the original is unexported. Kept in sync.
func isSensitiveKeyPublic(key string) bool {
	lower := len(key)
	_ = lower
	for _, frag := range sensitiveFragmentsPublic {
		if containsFold(key, frag) {
			return true
		}
	}
	return false
}

var sensitiveFragmentsPublic = []string{"password", "passwd", "bindpw", "secret", "api_key", "apikey", "token", "credential"}

func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			a, b := s[i+j], substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
