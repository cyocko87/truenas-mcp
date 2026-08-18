package tools

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleQueryAPIKeys(client *truenas.Client, args map[string]interface{}) (string, error) {
	result, err := client.Call("api_key.query")
	if err != nil {
		return "", err
	}

	var keys []map[string]interface{}
	if err := json.Unmarshal(result, &keys); err != nil {
		return "", fmt.Errorf("failed to parse api keys: %w", err)
	}

	simplified := make([]map[string]interface{}, 0, len(keys))
	for _, k := range keys {
		entry := map[string]interface{}{
			"id":       k["id"],
			"name":     k["name"],
			"username": k["username"],
		}
		if created, ok := k["created_at"].(map[string]interface{}); ok {
			entry["created_at"] = created["$date"]
		}
		simplified = append(simplified, entry)
	}

	response := map[string]interface{}{
		"api_keys":   simplified,
		"key_count":  len(simplified),
		"note":       "API key values are never returned. Use create_api_key once, save it securely.",
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleCreateAPIKey(client *truenas.Client, args map[string]interface{}) (string, error) {
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("name is required")
	}

	username, _ := args["username"].(string)
	if username == "" {
		// Default to the authenticated user (the devin-mcp service account).
		username = "devin-mcp"
	}

	payload := map[string]interface{}{
		"name":     name,
		"username": username,
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "api_key.create",
			"payload":   payload,
			"note":      "Preview only. No key created.",
			"warning":   "Real call returns the key ONCE. Save it immediately - it cannot be retrieved later.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	// WARNING: TrueNAS returns the key in the response. We must NOT pass it
	// back to the agent. We return only the key id and a redaction notice.
	result, err := client.Call("api_key.create", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create api key: %w", err)
	}

	var keyResp map[string]interface{}
	if err := json.Unmarshal(result, &keyResp); err != nil {
		return "", fmt.Errorf("failed to parse api key response: %w", err)
	}

	// Extract id, redact the actual key.
	response := map[string]interface{}{
		"success":  true,
		"name":     name,
		"username": username,
		"key_id":   keyResp["id"],
		"warning":  "API key created. The key value was REDACTED and not exposed to the agent. Retrieve it from TrueNAS Web UI > System Settings > API Keys, or re-run with a script that writes it to a secure location.",
	}
	if id, ok := keyResp["id"].(float64); ok {
		response["key_id"] = int64(id)
	}

	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleRevokeAPIKey(client *truenas.Client, args map[string]interface{}) (string, error) {
	keyID, err := resolveAPIKeyID(client, args)
	if err != nil {
		return "", err
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "api_key.delete",
			"key_id":    keyID,
			"note":      "Preview only. No key revoked.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("api_key.delete", keyID)
	if err != nil {
		return "", fmt.Errorf("failed to revoke api key: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"key_id":  keyID,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func resolveAPIKeyID(client *truenas.Client, args map[string]interface{}) (int64, error) {
	if id, ok := args["key_id"].(float64); ok && id > 0 {
		return int64(id), nil
	}
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return 0, fmt.Errorf("key_id or name is required")
	}
	result, err := client.Call("api_key.query")
	if err != nil {
		return 0, fmt.Errorf("failed to query api keys: %w", err)
	}
	var keys []map[string]interface{}
	if err := json.Unmarshal(result, &keys); err != nil {
		return 0, fmt.Errorf("failed to parse api keys: %w", err)
	}
	for _, k := range keys {
		if n, ok := k["name"].(string); ok && strings.EqualFold(n, name) {
			if id, ok := k["id"].(float64); ok {
				return int64(id), nil
			}
		}
	}
	return 0, fmt.Errorf("api key named %s not found", name)
}
