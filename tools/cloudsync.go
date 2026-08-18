package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleQueryCloudSync(client *truenas.Client, args map[string]interface{}) (string, error) {
	filters := []interface{}{}
	if name, ok := args["name"].(string); ok && name != "" {
		filters = append(filters, []interface{}{"description", "~", name})
	}

	options := map[string]interface{}{}
	if orderBy, ok := args["order_by"].(string); ok && orderBy != "" {
		options["order_by"] = []interface{}{orderBy}
	} else {
		options["order_by"] = []interface{}{"description"}
	}

	result, err := client.Call("cloudsync.query", filters, options)
	if err != nil {
		return "", err
	}

	var tasks []map[string]interface{}
	if err := json.Unmarshal(result, &tasks); err != nil {
		return "", fmt.Errorf("failed to parse cloud sync tasks: %w", err)
	}

	simplified := make([]map[string]interface{}, 0, len(tasks))
	for _, t := range tasks {
		entry := map[string]interface{}{
			"id":            t["id"],
			"description":   t["description"],
			"direction":     t["direction"],
			"transfer_mode": t["transfer_mode"],
			"enabled":       t["enabled"],
		}
		if credentials, ok := t["credentials"].(float64); ok {
			entry["credentials_id"] = int64(credentials)
		}
		simplified = append(simplified, entry)
	}

	response := map[string]interface{}{
		"cloudsync_tasks": simplified,
		"task_count":      len(simplified),
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleCreateCloudSync(client *truenas.Client, args map[string]interface{}) (string, error) {
	description, ok := args["description"].(string)
	if !ok || description == "" {
		return "", fmt.Errorf("description is required")
	}
	direction, ok := args["direction"].(string)
	if !ok || direction == "" {
		return "", fmt.Errorf("direction is required: PUSH or PULL")
	}
	transferMode, ok := args["transfer_mode"].(string)
	if !ok || transferMode == "" {
		transferMode = "SYNC"
	}
	credentials, ok := args["credentials"].(float64)
	if !ok || credentials <= 0 {
		return "", fmt.Errorf("credentials (credential provider id) is required")
	}

	payload := map[string]interface{}{
		"description":   description,
		"direction":     direction,
		"transfer_mode": transferMode,
		"credentials":   int64(credentials),
	}

	if path, ok := args["path"].(string); ok && path != "" {
		payload["path"] = path
	} else {
		return "", fmt.Errorf("path is required (local dataset path)")
	}

	if schedule, ok := args["schedule"].(map[string]interface{}); ok {
		payload["schedule"] = schedule
	}
	if encryption, ok := args["encryption"].(bool); ok {
		payload["encryption"] = encryption
	}
	if filenameEncryption, ok := args["filename_encryption"].(bool); ok {
		payload["filename_encryption"] = filenameEncryption
	}
	if argsSlice, ok := args["args"].([]interface{}); ok {
		payload["args"] = argsSlice
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "cloudsync.create",
			"payload":   payload,
			"note":      "Preview only. No cloud sync task created.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("cloudsync.create", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create cloud sync task: %w", err)
	}

	response := map[string]interface{}{
		"success":     true,
		"description": description,
		"result":      result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}
