package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/truenas/truenas-mcp/truenas"
)

// handleSyncSSHKey fetches an SSH public key from a blind credential source
// (aac or Bitwarden CLI) and writes it to a TrueNAS user's sshpubkey field.
//
// The key material is fetched by truenas-mcp itself (subprocess), held only in
// process memory for the duration of the user.update call, and never returned
// to the calling agent. The agent receives only a fingerprint + success flag.
//
// Backends:
//   - aac:   calls `aac run --domain <key_ref> --user <username> --output json`
//            (or --env SSH_KEY=<field>) and parses the credential. Requires
//            AAC_TOKEN env var on the truenas-mcp process.
//   - bw:    calls `bw get item <key_ref>` and extracts the ssh key from a
//            custom field named "sshkey" (or "ssh_public_key", "pubkey").
//            Requires BW_PASSWORD + logged-in bw CLI.
//   - file:  reads the key from a path on disk (gitignored). Useful for
//            air-gapped setups. Path must be absolute.
//
// args:
//   username (required) - TrueNAS user to update
//   backend  (default aac) - aac | bw | file
//   key_ref  (required) - domain (aac), item name/id (bw), or path (file)
//   field    (optional) - credential field name for aac/bw (default: sshkey)
//   dry_run  (optional)
func handleSyncSSHKey(client *truenas.Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	backend, _ := args["backend"].(string)
	if backend == "" {
		backend = "aac"
	}

	keyRef, ok := args["key_ref"].(string)
	if !ok || keyRef == "" {
		return "", fmt.Errorf("key_ref is required (domain for aac, item name/id for bw, path for file)")
	}

	field, _ := args["field"].(string)
	if field == "" {
		field = "sshkey"
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":     true,
			"operation":   "sync_ssh_key",
			"username":    username,
			"backend":     backend,
			"key_ref":     keyRef,
			"field":       field,
			"note":        "Preview only. No key fetched, no user updated.",
			"key_visible": false,
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	// 1. Fetch key material into local var (never logged, never returned).
	pubKey, err := fetchSSHKey(backend, keyRef, field, username)
	if err != nil {
		return "", fmt.Errorf("failed to fetch ssh key from %s backend: %w", backend, err)
	}
	if pubKey == "" {
		return "", fmt.Errorf("backend %s returned empty key for ref %q", backend, keyRef)
	}
	defer func() { pubKey = "" }() // best-effort scrub

	// 2. Resolve user id.
	userID, err := resolveUserID(client, args)
	if err != nil {
		return "", err
	}

	// 3. Push key to TrueNAS. The key transits the websocket to TrueNAS but
	//    is not returned to the agent.
	_, err = client.Call("user.update", userID, map[string]interface{}{
		"sshpubkey": pubKey,
	})
	if err != nil {
		return "", fmt.Errorf("failed to set sshpubkey on user %s: %w", username, err)
	}

	// 4. Return only fingerprint + success. Never the key.
	response := map[string]interface{}{
		"success":             true,
		"username":            username,
		"sshpubkey_set":       true,
		"sshpubkey_fingerprint": sshFingerprint(pubKey),
		"backend":             backend,
		"note":                "Key fetched blind and pushed to TrueNAS. Key material not exposed.",
	}

	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

// fetchSSHKey retrieves the public key from the named backend.
// The returned string is the raw ssh public key line. It must be scrubbed by
// the caller after use.
func fetchSSHKey(backend, keyRef, field, username string) (string, error) {
	switch strings.ToLower(backend) {
	case "aac":
		return fetchKeyViaAAC(keyRef, field, username)
	case "bw":
		return fetchKeyViaBitwarden(keyRef, field)
	case "file":
		return fetchKeyFromFile(keyRef)
	default:
		return "", fmt.Errorf("unknown backend %q (use aac, bw, or file)", backend)
	}
}

// fetchKeyViaAAC calls the aac CLI to retrieve a credential and extracts the
// ssh key from the named field. Uses --output json for single-shot mode.
func fetchKeyViaAAC(domain, field, username string) (string, error) {
	aacPath, err := exec.LookPath("aac")
	if err != nil {
		// Fall back to known install location.
		alt := `C:\Users\jakey\git\vaultwarden-stack\agent-access\bin\aac.exe`
		if _, statErr := os.Stat(alt); statErr == nil {
			aacPath = alt
		} else {
			return "", fmt.Errorf("aac binary not found in PATH or at %s", alt)
		}
	}

	// aac run --domain <domain> --user <username> --output json
	// (single-shot: no command, prints credential as JSON)
	cmd := exec.Command(aacPath, "run",
		"--domain", domain,
		"--user", username,
		"--output", "json",
		"--timeout", "60",
	)
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("aac run failed: %w (stderr may contain connection details)", err)
	}

	var cred map[string]interface{}
	if err := json.Unmarshal(out, &cred); err != nil {
		return "", fmt.Errorf("failed to parse aac output: %w", err)
	}

	// Try the requested field, then common fallbacks.
	candidates := []string{field, "sshkey", "ssh_public_key", "pubkey", "notes"}
	for _, f := range candidates {
		if v, ok := cred[f].(string); ok && v != "" {
			return extractSSHKeyBody(v), nil
		}
	}
	return "", fmt.Errorf("aac credential for domain %q has no field %q (fields present: %v)", domain, field, jsonKeys(cred))
}

// fetchKeyViaBitwarden calls the bw CLI to retrieve an item and extracts the
// ssh key from a custom field. Requires BW_PASSWORD env + logged-in session.
func fetchKeyViaBitwarden(itemRef, field string) (string, error) {
	bwPath, err := exec.LookPath("bw")
	if err != nil {
		alt := `C:\Users\jakey\AppData\Roaming\npm\bw.cmd`
		if _, statErr := os.Stat(alt); statErr == nil {
			bwPath = alt
		} else {
			return "", fmt.Errorf("bw CLI not found in PATH or at %s", alt)
		}
	}

	cmd := exec.Command(bwPath, "get", "item", itemRef)
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("bw get item failed: %w", err)
	}

	var item map[string]interface{}
	if err := json.Unmarshal(out, &item); err != nil {
		return "", fmt.Errorf("failed to parse bw item: %w", err)
	}

	// Check custom fields first.
	if fields, ok := item["fields"].([]interface{}); ok {
		candidates := []string{field, "sshkey", "ssh_public_key", "pubkey"}
		for _, f := range fields {
			if fm, ok := f.(map[string]interface{}); ok {
				name, _ := fm["name"].(string)
				for _, c := range candidates {
					if strings.EqualFold(name, c) {
						if val, ok := fm["value"].(string); ok && val != "" {
							return extractSSHKeyBody(val), nil
						}
					}
				}
			}
		}
	}
	// Fallback: notes field.
	if notes, ok := item["notes"].(string); ok && notes != "" {
		if k := extractSSHKeyBody(notes); k != "" {
			return k, nil
		}
	}
	return "", fmt.Errorf("bw item %q has no ssh key in field %q or fallbacks", itemRef, field)
}

// fetchKeyFromFile reads a public key from a file path. The file must be
// outside agent-readable dirs (gitignored). Only the first ssh-key line is used.
func fetchKeyFromFile(path string) (string, error) {
	if !strings.HasPrefix(path, "/") && !strings.Contains(path, ":\\") {
		return "", fmt.Errorf("file path must be absolute: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file %s: %w", path, err)
	}
	return extractSSHKeyBody(string(data)), nil
}

// extractSSHKeyBody pulls the first ssh public key line from a blob.
// Handles multi-line text (e.g. notes field with extra prose).
func extractSSHKeyBody(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ssh-") || strings.HasPrefix(line, "ecdsa-") || strings.HasPrefix(line, "sk-ssh-") || strings.HasPrefix(line, "sk-ecdsa-") {
			return line
		}
	}
	// If single-line and looks like a key, return as-is.
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "ssh-") || strings.HasPrefix(trimmed, "ecdsa-") || strings.HasPrefix(trimmed, "sk-") {
		return trimmed
	}
	return ""
}

func jsonKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// init ensures this file's time import is used (silences unused import if
// future edits remove the only time reference).
var _ = time.Second
