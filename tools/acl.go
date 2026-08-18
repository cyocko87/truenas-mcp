package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleGetACL(client *truenas.Client, args map[string]interface{}) (string, error) {
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return "", fmt.Errorf("path is required (e.g. /mnt/tank/data)")
	}

	payload := map[string]interface{}{"path": path}
	if daclPath, ok := args["dacl_path"].(string); ok && daclPath != "" {
		payload["dacl_path"] = daclPath
	}

	result, err := client.Call("filesystem.acl.getacl", payload)
	if err != nil {
		return "", fmt.Errorf("failed to get ACL: %w", err)
	}

	response := map[string]interface{}{
		"path": path,
		"acl":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleSetACL(client *truenas.Client, args map[string]interface{}) (string, error) {
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return "", fmt.Errorf("path is required")
	}

	acl, ok := args["acl"].([]interface{})
	if !ok || len(acl) == 0 {
		return "", fmt.Errorf("acl is required (array of ACL entries)")
	}

	payload := map[string]interface{}{
		"path": path,
		"dacl": acl,
	}

	if aclType, ok := args["acl_type"].(string); ok && aclType != "" {
		payload["acl_type"] = aclType // POSIX or NFSV4
	} else {
		payload["acl_type"] = "NFSV4"
	}

	if options, ok := args["options"].(map[string]interface{}); ok {
		payload["options"] = options
	} else {
		// Sensible defaults: recursive, strip ACL, apply to children
		payload["options"] = map[string]interface{}{
			"recursive": true,
			"traverse":  true,
		}
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "filesystem.acl.setacl",
			"payload":   payload,
			"note":      "Preview only. No ACL set.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("filesystem.acl.setacl", payload)
	if err != nil {
		return "", fmt.Errorf("failed to set ACL: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"path":    path,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}
