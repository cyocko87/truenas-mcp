package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

// handleDeleteSMBShare removes an SMB share by id or name.
func handleDeleteSMBShare(client *truenas.Client, args map[string]interface{}) (string, error) {
	shareID, err := resolveSMBShareID(client, args)
	if err != nil {
		return "", err
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "sharing.smb.delete",
			"share_id":  shareID,
			"note":      "Preview only. No share deleted.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("sharing.smb.delete", shareID)
	if err != nil {
		return "", fmt.Errorf("failed to delete SMB share: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"share_id": shareID,
		"result":   result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// handleUpdateSMBShare updates an SMB share configuration.
func handleUpdateSMBShare(client *truenas.Client, args map[string]interface{}) (string, error) {
	shareID, err := resolveSMBShareID(client, args)
	if err != nil {
		return "", err
	}

	payload := buildSMBUpdatePayload(args)
	if len(payload) == 0 {
		return "", fmt.Errorf("no fields to update")
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "sharing.smb.update",
			"share_id":  shareID,
			"payload":   payload,
			"note":      "Preview only. No share updated.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("sharing.smb.update", shareID, payload)
	if err != nil {
		return "", fmt.Errorf("failed to update SMB share: %w", err)
	}

	var updated map[string]interface{}
	if err := json.Unmarshal(result, &updated); err != nil {
		return "", fmt.Errorf("failed to parse update response: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"share_id": shareID,
		"name":     updated["name"],
		"path":     updated["path"],
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// handleDeleteNFSShare removes an NFS share by id.
func handleDeleteNFSShare(client *truenas.Client, args map[string]interface{}) (string, error) {
	shareID, err := resolveNFSShareID(client, args)
	if err != nil {
		return "", err
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "sharing.nfs.delete",
			"share_id":  shareID,
			"note":      "Preview only. No share deleted.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("sharing.nfs.delete", shareID)
	if err != nil {
		return "", fmt.Errorf("failed to delete NFS share: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"share_id": shareID,
		"result":   result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// handleUpdateNFSShare updates an NFS share configuration.
func handleUpdateNFSShare(client *truenas.Client, args map[string]interface{}) (string, error) {
	shareID, err := resolveNFSShareID(client, args)
	if err != nil {
		return "", err
	}

	payload := buildNFSUpdatePayload(args)
	if len(payload) == 0 {
		return "", fmt.Errorf("no fields to update")
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "sharing.nfs.update",
			"share_id":  shareID,
			"payload":   payload,
			"note":      "Preview only. No share updated.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("sharing.nfs.update", shareID, payload)
	if err != nil {
		return "", fmt.Errorf("failed to update NFS share: %w", err)
	}

	var updated map[string]interface{}
	if err := json.Unmarshal(result, &updated); err != nil {
		return "", fmt.Errorf("failed to parse update response: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"share_id": shareID,
		"path":     updated["path"],
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func resolveSMBShareID(client *truenas.Client, args map[string]interface{}) (int64, error) {
	if id, ok := args["share_id"].(float64); ok && id > 0 {
		return int64(id), nil
	}
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return 0, fmt.Errorf("share_id or name is required")
	}
	filters := []interface{}{[]interface{}{"name", "=", name}}
	options := map[string]interface{}{"get": true}
	result, err := client.Call("sharing.smb.query", filters, options)
	if err != nil {
		return 0, fmt.Errorf("failed to look up SMB share %s: %w", name, err)
	}
	var share map[string]interface{}
	if err := json.Unmarshal(result, &share); err != nil {
		return 0, fmt.Errorf("failed to parse share lookup: %w", err)
	}
	if share == nil {
		return 0, fmt.Errorf("SMB share %s not found", name)
	}
	id, ok := share["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("SMB share %s has no id", name)
	}
	return int64(id), nil
}

func resolveNFSShareID(client *truenas.Client, args map[string]interface{}) (int64, error) {
	if id, ok := args["share_id"].(float64); ok && id > 0 {
		return int64(id), nil
	}
	// NFS shares don't have names; require share_id or path.
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return 0, fmt.Errorf("share_id or path is required for NFS")
	}
	filters := []interface{}{[]interface{}{"path", "=", path}}
	options := map[string]interface{}{"get": true}
	result, err := client.Call("sharing.nfs.query", filters, options)
	if err != nil {
		return 0, fmt.Errorf("failed to look up NFS share by path %s: %w", path, err)
	}
	var share map[string]interface{}
	if err := json.Unmarshal(result, &share); err != nil {
		return 0, fmt.Errorf("failed to parse share lookup: %w", err)
	}
	if share == nil {
		return 0, fmt.Errorf("NFS share with path %s not found", path)
	}
	id, ok := share["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("NFS share %s has no id", path)
	}
	return int64(id), nil
}

func buildSMBUpdatePayload(args map[string]interface{}) map[string]interface{} {
	payload := map[string]interface{}{}
	stringFields := []string{"comment", "path", "home", "purpose", "auxsmbconf"}
	for _, f := range stringFields {
		if v, ok := args[f].(string); ok && v != "" {
			payload[f] = v
		}
	}
	boolFields := []string{"enabled", "ro", "browsable", "guestok", "abe", "aclmode", "auxsmbconf"}
	for _, f := range boolFields {
		if v, ok := args[f].(bool); ok {
			payload[f] = v
		}
	}
	return payload
}

func buildNFSUpdatePayload(args map[string]interface{}) map[string]interface{} {
	payload := map[string]interface{}{}
	stringFields := []string{"comment", "security", "maproot_user", "maproot_group", "mapall_user", "mapall_group"}
	for _, f := range stringFields {
		if v, ok := args[f].(string); ok && v != "" {
			payload[f] = v
		}
	}
	boolFields := []string{"enabled", "ro"}
	for _, f := range boolFields {
		if v, ok := args[f].(bool); ok {
			payload[f] = v
		}
	}
	if networks, ok := args["networks"].([]interface{}); ok {
		payload["networks"] = networks
	}
	if hosts, ok := args["hosts"].([]interface{}); ok {
		payload["hosts"] = hosts
	}
	return payload
}
