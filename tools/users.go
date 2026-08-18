package tools

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/truenas/truenas-mcp/truenas"
)

// handleQueryUsers lists TrueNAS local users with optional filtering.
func handleQueryUsers(client *truenas.Client, args map[string]interface{}) (string, error) {
	filters := []interface{}{}
	if username, ok := args["username"].(string); ok && username != "" {
		filters = append(filters, []interface{}{"username", "~", username})
	}
	if uid, ok := args["uid"].(float64); ok && uid > 0 {
		filters = append(filters, []interface{}{"uid", "=", int64(uid)})
	}

	options := map[string]interface{}{}
	if orderBy, ok := args["order_by"].(string); ok && orderBy != "" {
		options["order_by"] = []interface{}{orderBy}
	} else {
		options["order_by"] = []interface{}{"username"}
	}

	result, err := client.Call("user.query", filters, options)
	if err != nil {
		return "", err
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(result, &users); err != nil {
		return "", fmt.Errorf("failed to parse users: %w", err)
	}

	simplified := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		simplified = append(simplified, simplifyUser(u))
	}

	limit := 50
	if l, ok := args["limit"].(float64); ok && l > 0 {
		limit = int(l)
	}
	if len(simplified) > limit {
		simplified = simplified[:limit]
	}

	response := map[string]interface{}{
		"users":       simplified,
		"user_count":  len(simplified),
		"total_users": len(users),
	}

	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// handleGetUser returns a single user by username or uid.
func handleGetUser(client *truenas.Client, args map[string]interface{}) (string, error) {
	filters := []interface{}{}
	if username, ok := args["username"].(string); ok && username != "" {
		filters = append(filters, []interface{}{"username", "=", username})
	} else if uid, ok := args["uid"].(float64); ok && uid > 0 {
		filters = append(filters, []interface{}{"uid", "=", int64(uid)})
	} else {
		return "", fmt.Errorf("username or uid is required")
	}

	options := map[string]interface{}{"get": true}
	result, err := client.Call("user.query", filters, options)
	if err != nil {
		return "", err
	}

	var user map[string]interface{}
	if err := json.Unmarshal(result, &user); err != nil {
		return "", fmt.Errorf("failed to parse user: %w", err)
	}
	if user == nil {
		return "", fmt.Errorf("user not found")
	}

	simplified := simplifyUser(user)
	// Indicate whether an ssh public key is set, but never echo the key body.
	if pub, ok := user["sshpubkey"].(string); ok && pub != "" {
		simplified["sshpubkey_set"] = true
		simplified["sshpubkey_fingerprint"] = sshFingerprint(pub)
	} else {
		simplified["sshpubkey_set"] = false
	}

	formatted, err := json.MarshalIndent(simplified, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// handleCreateUser creates a local TrueNAS user.
// sshpubkey may be passed directly (it is a public key, not secret) but the
// preferred blind path is sync_ssh_key, which pulls the key from Vaultwarden
// so the calling agent never sees the key material.
func handleCreateUser(client *truenas.Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}
	if err := validateUsername(username); err != nil {
		return "", err
	}

	fullName, _ := args["full_name"].(string)
	if fullName == "" {
		fullName = username
	}

	payload := map[string]interface{}{
		"username":  username,
		"full_name": fullName,
	}

	// password is a secret: accept it (TrueNAS requires one for local users
	// unless password_disabled=true), but never log it. The client layer
	// already redacts "password" keys in debug logs.
	if passwordDisabled, ok := args["password_disabled"].(bool); ok && passwordDisabled {
		payload["password_disabled"] = true
	} else if password, ok := args["password"].(string); ok && password != "" {
		payload["password"] = password
	} else {
		// Default: disable password login. Use sync_ssh_key or update_user to
		// set an ssh key for access. Caller can override with password or
		// password_disabled=false + password.
		payload["password_disabled"] = true
	}

	if uid, ok := args["uid"].(float64); ok && uid > 0 {
		payload["uid"] = int64(uid)
	}
	if group, ok := args["group"].(string); ok && group != "" {
		payload["group"] = group
	}
	if gid, ok := args["gid"].(float64); ok && gid > 0 {
		payload["gid"] = int64(gid)
	}
	if shell, ok := args["shell"].(string); ok && shell != "" {
		payload["shell"] = shell
	}
	if home, ok := args["home"].(string); ok && home != "" {
		payload["home"] = home
	}
	if email, ok := args["email"].(string); ok && email != "" {
		payload["email"] = email
	}
	if smb, ok := args["smb"].(bool); ok {
		payload["smb"] = smb
	}
	if locked, ok := args["locked"].(bool); ok {
		payload["locked"] = locked
	}
	if sshpubkey, ok := args["sshpubkey"].(string); ok && sshpubkey != "" {
		payload["sshpubkey"] = sshpubkey
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "user.create",
			"payload":   redactUserPayload(payload),
			"note":      "Preview only. No user created.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("user.create", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	var created map[string]interface{}
	if err := json.Unmarshal(result, &created); err != nil {
		return "", fmt.Errorf("failed to parse create response: %w", err)
	}

	response := map[string]interface{}{
		"success":   true,
		"username":  created["username"],
		"uid":       created["uid"],
		"full_name": created["full_name"],
	}
	if id, ok := created["id"]; ok {
		response["user_id"] = id
	}

	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// handleUpdateUser updates an existing local TrueNAS user.
// sshpubkey may be supplied directly (public key) or via sync_ssh_key (blind).
func handleUpdateUser(client *truenas.Client, args map[string]interface{}) (string, error) {
	userID, err := resolveUserID(client, args)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{}
	stringFields := []string{"full_name", "shell", "home", "email", "sshpubkey", "group"}
	for _, f := range stringFields {
		if v, ok := args[f].(string); ok && v != "" {
			payload[f] = v
		}
	}
	intFields := []string{"uid", "gid"}
	for _, f := range intFields {
		if v, ok := args[f].(float64); ok && v > 0 {
			payload[f] = int64(v)
		}
	}
	boolFields := []string{"smb", "locked", "password_disabled", "ssh_password_enabled"}
	for _, f := range boolFields {
		if v, ok := args[f].(bool); ok {
			payload[f] = v
		}
	}
	if password, ok := args["password"].(string); ok && password != "" {
		payload["password"] = password
	}
	// Allow clearing the ssh public key.
	if clearSSH, ok := args["clear_sshpubkey"].(bool); ok && clearSSH {
		payload["sshpubkey"] = ""
	}

	if len(payload) == 0 {
		return "", fmt.Errorf("no fields to update")
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "user.update",
			"user_id":   userID,
			"payload":   redactUserPayload(payload),
			"note":      "Preview only. No user updated.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("user.update", userID, payload)
	if err != nil {
		return "", fmt.Errorf("failed to update user: %w", err)
	}

	var updated map[string]interface{}
	if err := json.Unmarshal(result, &updated); err != nil {
		return "", fmt.Errorf("failed to parse update response: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"username": updated["username"],
		"uid":      updated["uid"],
	}
	if pub, ok := updated["sshpubkey"].(string); ok {
		response["sshpubkey_set"] = pub != ""
		if pub != "" {
			response["sshpubkey_fingerprint"] = sshFingerprint(pub)
		}
	}

	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// handleDeleteUser deletes a local TrueNAS user.
func handleDeleteUser(client *truenas.Client, args map[string]interface{}) (string, error) {
	userID, err := resolveUserID(client, args)
	if err != nil {
		return "", err
	}

	options := map[string]interface{}{}
	if delGroup, ok := args["delete_group"].(bool); ok {
		options["delete_group"] = delGroup
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "user.delete",
			"user_id":   userID,
			"options":   options,
			"note":      "Preview only. No user deleted.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("user.delete", userID, options)
	if err != nil {
		return "", fmt.Errorf("failed to delete user: %w", err)
	}

	response := map[string]interface{}{
		"success": true,
		"user_id": userID,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// resolveUserID finds the numeric user id from username or uid args.
func resolveUserID(client *truenas.Client, args map[string]interface{}) (int64, error) {
	if uid, ok := args["uid"].(float64); ok && uid > 0 {
		return int64(uid), nil
	}
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return 0, fmt.Errorf("username or uid is required")
	}
	filters := []interface{}{[]interface{}{"username", "=", username}}
	options := map[string]interface{}{"get": true}
	result, err := client.Call("user.query", filters, options)
	if err != nil {
		return 0, fmt.Errorf("failed to look up user %s: %w", username, err)
	}
	var user map[string]interface{}
	if err := json.Unmarshal(result, &user); err != nil {
		return 0, fmt.Errorf("failed to parse user lookup: %w", err)
	}
	if user == nil {
		return 0, fmt.Errorf("user %s not found", username)
	}
	uid, ok := user["uid"].(float64)
	if !ok {
		return 0, fmt.Errorf("user %s has no uid", username)
	}
	return int64(uid), nil
}

// simplifyUser extracts the relevant non-secret fields from a raw user object.
// The ssh public key body is never included; only whether one is set.
func simplifyUser(u map[string]interface{}) map[string]interface{} {
	summary := map[string]interface{}{
		"username":  u["username"],
		"uid":       u["uid"],
		"full_name": u["full_name"],
	}
	if home, ok := u["home"].(string); ok {
		summary["home"] = home
	}
	if shell, ok := u["shell"].(string); ok {
		summary["shell"] = shell
	}
	if email, ok := u["email"].(string); ok {
		summary["email"] = email
	}
	if smb, ok := u["smb"].(bool); ok {
		summary["smb"] = smb
	}
	if locked, ok := u["locked"].(bool); ok {
		summary["locked"] = locked
	}
	if pwdDisabled, ok := u["password_disabled"].(bool); ok {
		summary["password_disabled"] = pwdDisabled
	}
	if sshPwd, ok := u["ssh_password_enabled"].(bool); ok {
		summary["ssh_password_enabled"] = sshPwd
	}
	if group, ok := u["group"].(map[string]interface{}); ok {
		if gname, ok := group["name"].(string); ok {
			summary["group"] = gname
		}
	} else if gname, ok := u["group"].(string); ok {
		summary["group"] = gname
	}
	if pub, ok := u["sshpubkey"].(string); ok && pub != "" {
		summary["sshpubkey_set"] = true
		summary["sshpubkey_fingerprint"] = sshFingerprint(pub)
	} else {
		summary["sshpubkey_set"] = false
	}
	return summary
}

// redactUserPayload returns a copy of payload with password masked, for dry-run previews.
func redactUserPayload(payload map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(payload))
	for k, v := range payload {
		if strings.Contains(strings.ToLower(k), "password") {
			out[k] = "[REDACTED]"
		} else if k == "sshpubkey" {
			if s, ok := v.(string); ok && s != "" {
				out[k] = fmt.Sprintf("[SET: %d chars, fp=%s]", len(s), sshFingerprint(s))
			} else {
				out[k] = v
			}
		} else {
			out[k] = v
		}
	}
	return out
}

// sshFingerprint returns a short, non-reversible fingerprint of an ssh public key.
// Format: first 12 chars of base64 body + key type. Not the key itself.
func sshFingerprint(pub string) string {
	pub = strings.TrimSpace(pub)
	if pub == "" {
		return ""
	}
	parts := strings.Fields(pub)
	if len(parts) < 2 {
		return "[unparseable]"
	}
	keyType := parts[0]
	body := parts[1]
	if len(body) > 12 {
		body = body[:12]
	}
	return fmt.Sprintf("%s:%s...", keyType, body)
}

// validateUsername checks the username format.
func validateUsername(name string) error {
	if name == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(name) > 32 {
		return fmt.Errorf("username too long (max 32 chars)")
	}
	valid := regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
	if !valid.MatchString(name) {
		return fmt.Errorf("username must start with a letter or underscore and contain only lowercase letters, digits, underscores, or hyphens")
	}
	return nil
}
