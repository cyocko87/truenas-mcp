package tools

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleQueryGroups(client *truenas.Client, args map[string]interface{}) (string, error) {
	filters := []interface{}{}
	if name, ok := args["name"].(string); ok && name != "" {
		filters = append(filters, []interface{}{"name", "~", name})
	}
	if gid, ok := args["gid"].(float64); ok && gid > 0 {
		filters = append(filters, []interface{}{"gid", "=", int64(gid)})
	}

	options := map[string]interface{}{}
	// Note: group.query uses bsdgrp_ prefix internally; skip order_by to
	// avoid KeyError on column resolution.

	result, err := client.Call("group.query", filters, options)
	if err != nil {
		return "", err
	}

	var groups []map[string]interface{}
	if err := json.Unmarshal(result, &groups); err != nil {
		return "", fmt.Errorf("failed to parse groups: %w", err)
	}

	simplified := make([]map[string]interface{}, 0, len(groups))
	for _, g := range groups {
		simplified = append(simplified, simplifyGroup(g))
	}

	limit := 50
	if l, ok := args["limit"].(float64); ok && l > 0 {
		limit = int(l)
	}
	if len(simplified) > limit {
		simplified = simplified[:limit]
	}

	response := map[string]interface{}{
		"groups":       simplified,
		"group_count":  len(simplified),
		"total_groups": len(groups),
	}

	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleCreateGroup(client *truenas.Client, args map[string]interface{}) (string, error) {
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return "", fmt.Errorf("name is required")
	}
	if err := validateGroupName(name); err != nil {
		return "", err
	}

	payload := map[string]interface{}{"name": name}
	if gid, ok := args["gid"].(float64); ok && gid > 0 {
		payload["gid"] = int64(gid)
	}
	if smb, ok := args["smb"].(bool); ok {
		payload["smb"] = smb
	}
	if users, ok := args["users"].([]interface{}); ok && len(users) > 0 {
		payload["users"] = users
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "group.create",
			"payload":   payload,
			"note":      "Preview only. No group created.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("group.create", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create group: %w", err)
	}

	var created map[string]interface{}
	if err := json.Unmarshal(result, &created); err != nil {
		return "", fmt.Errorf("failed to parse create response: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"name":    created["name"],
		"gid":     created["gid"],
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleUpdateGroup(client *truenas.Client, args map[string]interface{}) (string, error) {
	groupID, err := resolveGroupID(client, args)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{}
	if name, ok := args["name"].(string); ok && name != "" {
		payload["name"] = name
	}
	if gid, ok := args["gid"].(float64); ok && gid > 0 {
		payload["gid"] = int64(gid)
	}
	if smb, ok := args["smb"].(bool); ok {
		payload["smb"] = smb
	}
	if users, ok := args["users"].([]interface{}); ok {
		payload["users"] = users
	}

	if len(payload) == 0 {
		return "", fmt.Errorf("no fields to update")
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "group.update",
			"group_id":  groupID,
			"payload":   payload,
			"note":      "Preview only. No group updated.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("group.update", groupID, payload)
	if err != nil {
		return "", fmt.Errorf("failed to update group: %w", err)
	}

	var updated map[string]interface{}
	if err := json.Unmarshal(result, &updated); err != nil {
		return "", fmt.Errorf("failed to parse update response: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"name":    updated["name"],
		"gid":     updated["gid"],
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleDeleteGroup(client *truenas.Client, args map[string]interface{}) (string, error) {
	groupID, err := resolveGroupID(client, args)
	if err != nil {
		return "", err
	}

	options := map[string]interface{}{}
	if delUsers, ok := args["delete_users"].(bool); ok {
		options["delete_users"] = delUsers
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "group.delete",
			"group_id":  groupID,
			"options":   options,
			"note":      "Preview only. No group deleted.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("group.delete", groupID, options)
	if err != nil {
		return "", fmt.Errorf("failed to delete group: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"group_id": groupID,
		"result":   result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func resolveGroupID(client *truenas.Client, args map[string]interface{}) (int64, error) {
	if gid, ok := args["gid"].(float64); ok && gid > 0 {
		return int64(gid), nil
	}
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return 0, fmt.Errorf("name or gid is required")
	}
	filters := []interface{}{[]interface{}{"name", "=", name}}
	options := map[string]interface{}{"get": true}
	result, err := client.Call("group.query", filters, options)
	if err != nil {
		return 0, fmt.Errorf("failed to look up group %s: %w", name, err)
	}
	var group map[string]interface{}
	if err := json.Unmarshal(result, &group); err != nil {
		return 0, fmt.Errorf("failed to parse group lookup: %w", err)
	}
	if group == nil {
		return 0, fmt.Errorf("group %s not found", name)
	}
	gid, ok := group["gid"].(float64)
	if !ok {
		return 0, fmt.Errorf("group %s has no gid", name)
	}
	return int64(gid), nil
}

func simplifyGroup(g map[string]interface{}) map[string]interface{} {
	summary := map[string]interface{}{
		"name": g["name"],
		"gid":  g["gid"],
	}
	if smb, ok := g["smb"].(bool); ok {
		summary["smb"] = smb
	}
	if users, ok := g["users"].([]interface{}); ok {
		summary["user_count"] = len(users)
	}
	return summary
}

func validateGroupName(name string) error {
	if name == "" {
		return fmt.Errorf("group name cannot be empty")
	}
	if len(name) > 32 {
		return fmt.Errorf("group name too long (max 32 chars)")
	}
	valid := regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
	if !valid.MatchString(name) {
		return fmt.Errorf("group name must start with letter/underscore, lowercase alphanumeric + hyphen/underscore only")
	}
	return nil
}
