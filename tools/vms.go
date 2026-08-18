package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleStartVM(client *truenas.Client, args map[string]interface{}) (string, error) {
	vmID, err := resolveVMID(client, args)
	if err != nil {
		return "", err
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "vm.start",
			"vm_id":     vmID,
			"note":      "Preview only. No VM started.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("vm.start", vmID)
	if err != nil {
		return "", fmt.Errorf("failed to start VM: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"vm_id":   vmID,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleStopVM(client *truenas.Client, args map[string]interface{}) (string, error) {
	vmID, err := resolveVMID(client, args)
	if err != nil {
		return "", err
	}

	force, _ := args["force"].(bool)

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "vm.stop",
			"vm_id":     vmID,
			"force":     force,
			"note":      "Preview only. No VM stopped.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	var result interface{}
	var err2 error
	if force {
		result, err2 = client.Call("vm.force_stop", vmID)
	} else {
		result, err2 = client.Call("vm.stop", vmID)
	}
	if err2 != nil {
		return "", fmt.Errorf("failed to stop VM: %w", err2)
	}

	response := map[string]interface{}{
		"success": true,
		"vm_id":   vmID,
		"force":   force,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleDeleteVM(client *truenas.Client, args map[string]interface{}) (string, error) {
	vmID, err := resolveVMID(client, args)
	if err != nil {
		return "", err
	}

	options := map[string]interface{}{}
	if zvol, ok := args["remove_zvols"].(bool); ok {
		options["remove_zvols"] = zvol
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "vm.delete",
			"vm_id":     vmID,
			"options":   options,
			"note":      "Preview only. No VM deleted.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("vm.delete", vmID, options)
	if err != nil {
		return "", fmt.Errorf("failed to delete VM: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"vm_id":   vmID,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func resolveVMID(client *truenas.Client, args map[string]interface{}) (int64, error) {
	if id, ok := args["vm_id"].(float64); ok && id > 0 {
		return int64(id), nil
	}
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return 0, fmt.Errorf("vm_id or name is required")
	}
	filters := []interface{}{[]interface{}{"name", "=", name}}
	options := map[string]interface{}{"get": true}
	result, err := client.Call("vm.query", filters, options)
	if err != nil {
		return 0, fmt.Errorf("failed to look up VM %s: %w", name, err)
	}
	var vm map[string]interface{}
	if err := json.Unmarshal(result, &vm); err != nil {
		return 0, fmt.Errorf("failed to parse VM lookup: %w", err)
	}
	if vm == nil {
		return 0, fmt.Errorf("VM %s not found", name)
	}
	id, ok := vm["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("VM %s has no id", name)
	}
	return int64(id), nil
}
