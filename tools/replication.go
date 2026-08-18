package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleQueryReplicationTasks(client *truenas.Client, args map[string]interface{}) (string, error) {
	filters := []interface{}{}
	if name, ok := args["name"].(string); ok && name != "" {
		filters = append(filters, []interface{}{"name", "~", name})
	}

	options := map[string]interface{}{}
	if orderBy, ok := args["order_by"].(string); ok && orderBy != "" {
		options["order_by"] = []interface{}{orderBy}
	} else {
		options["order_by"] = []interface{}{"name"}
	}

	result, err := client.Call("replication.query", filters, options)
	if err != nil {
		return "", err
	}

	var tasks []map[string]interface{}
	if err := json.Unmarshal(result, &tasks); err != nil {
		return "", fmt.Errorf("failed to parse replication tasks: %w", err)
	}

	simplified := make([]map[string]interface{}, 0, len(tasks))
	for _, t := range tasks {
		entry := map[string]interface{}{
			"id":        t["id"],
			"name":      t["name"],
			"direction": t["direction"],
			"transport": t["transport"],
			"enabled":   t["enabled"],
			"autosnap":  t["autosnap"],
			"recursive": t["recursive"],
		}
		if state, ok := t["state"].(map[string]interface{}); ok {
			entry["state"] = map[string]interface{}{
				"status":   state["status"],
				"datetime": state["datetime"],
			}
		}
		simplified = append(simplified, entry)
	}

	response := map[string]interface{}{
		"replication_tasks": simplified,
		"task_count":        len(simplified),
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleCreateReplicationTask(client *truenas.Client, args map[string]interface{}) (string, error) {
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("name is required")
	}
	sourceDS, ok := args["source_dataset"].(string)
	if !ok || sourceDS == "" {
		return "", fmt.Errorf("source_dataset is required")
	}
	targetDS, ok := args["target_dataset"].(string)
	if !ok || targetDS == "" {
		return "", fmt.Errorf("target_dataset is required")
	}

	payload := map[string]interface{}{
		"name":           name,
		"source_dataset": sourceDS,
		"target_dataset": targetDS,
		"direction":      "PUSH",
		"transport":      "SSH",
	}

	if direction, ok := args["direction"].(string); ok && direction != "" {
		payload["direction"] = direction
	}
	if transport, ok := args["transport"].(string); ok && transport != "" {
		payload["transport"] = transport
	}
	if sshCreds, ok := args["ssh_credentials"].(float64); ok && sshCreds > 0 {
		payload["ssh_credentials"] = int64(sshCreds)
	}
	if recursive, ok := args["recursive"].(bool); ok {
		payload["recursive"] = recursive
	} else {
		payload["recursive"] = true
	}
	if autosnap, ok := args["autosnap"].(bool); ok {
		payload["autosnap"] = autosnap
	}
	if namingSchema, ok := args["naming_schema"].(string); ok && namingSchema != "" {
		payload["naming_schema"] = namingSchema
	}
	if schedule, ok := args["schedule"].(map[string]interface{}); ok {
		payload["schedule"] = schedule
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "replication.create",
			"payload":   payload,
			"note":      "Preview only. No replication task created.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("replication.create", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create replication task: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"name":    name,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}
