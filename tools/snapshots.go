package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleCreateSnapshot(client *truenas.Client, args map[string]interface{}) (string, error) {
	dataset, ok := args["dataset"].(string)
	if !ok || dataset == "" {
		return "", fmt.Errorf("dataset is required (e.g. tank/data)")
	}

	name, _ := args["name"].(string)
	if name == "" {
		// Auto-generate: dataset@auto-YYYYMMDD-HHMMSS handled by TrueNAS if empty
		name = "auto-" + fmt.Sprintf("%d", 0)
	}

	payload := map[string]interface{}{
		"dataset": dataset,
		"name":    name,
	}

	if recursive, ok := args["recursive"].(bool); ok {
		payload["recursive"] = recursive
	}
	if vmwareSync, ok := args["vmware_sync"].(bool); ok {
		payload["vmware_sync"] = vmwareSync
	}
	if retainDays, ok := args["retain_days"].(float64); ok && retainDays > 0 {
		payload["retention_policy"] = map[string]interface{}{
			"retain": map[string]interface{}{
				"lifetime": fmt.Sprintf("P%dD", int(retainDays)),
			},
		}
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "zfs.snapshot.create",
			"payload":   payload,
			"note":      "Preview only. No snapshot created.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("zfs.snapshot.create", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"dataset":  dataset,
		"snapshot": name,
		"result":   result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleDeleteSnapshot(client *truenas.Client, args map[string]interface{}) (string, error) {
	snapshot, ok := args["snapshot"].(string)
	if !ok || snapshot == "" {
		return "", fmt.Errorf("snapshot is required (e.g. tank/data@snapname)")
	}

	options := map[string]interface{}{}
	if recursive, ok := args["recursive"].(bool); ok {
		options["recursive"] = recursive
	}
	if deferDestroy, ok := args["defer"].(bool); ok {
		options["defer"] = deferDestroy
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "zfs.snapshot.delete",
			"snapshot":  snapshot,
			"options":   options,
			"note":      "Preview only. No snapshot deleted.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("zfs.snapshot.delete", snapshot, options)
	if err != nil {
		return "", fmt.Errorf("failed to delete snapshot: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"snapshot": snapshot,
		"result":   result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleRollbackSnapshot(client *truenas.Client, args map[string]interface{}) (string, error) {
	snapshot, ok := args["snapshot"].(string)
	if !ok || snapshot == "" {
		return "", fmt.Errorf("snapshot is required (e.g. tank/data@snapname)")
	}

	options := map[string]interface{}{}
	if force, ok := args["force"].(bool); ok {
		options["force"] = force
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "zfs.snapshot.rollback",
			"snapshot":  snapshot,
			"options":   options,
			"warning":   "Rollback discards all data created AFTER this snapshot.",
			"note":      "Preview only. No rollback performed.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("zfs.snapshot.rollback", snapshot, options)
	if err != nil {
		return "", fmt.Errorf("failed to rollback snapshot: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"snapshot": snapshot,
		"result":   result,
		"warning":  "Dataset rolled back. All data after snapshot discarded.",
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}
