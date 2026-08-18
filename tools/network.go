package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleQueryNetworkInterfaces(client *truenas.Client, args map[string]interface{}) (string, error) {
	result, err := client.Call("interface.query")
	if err != nil {
		return "", err
	}

	var ifaces []map[string]interface{}
	if err := json.Unmarshal(result, &ifaces); err != nil {
		return "", fmt.Errorf("failed to parse interfaces: %w", err)
	}

	simplified := make([]map[string]interface{}, 0, len(ifaces))
	for _, i := range ifaces {
		entry := map[string]interface{}{
			"id":         i["id"],
			"name":       i["name"],
			"type":       i["type"],
			"enabled":    i["enabled"],
			"mtu":        i["mtu"],
			"cloned":     i["cloned"],
		}
		if state, ok := i["state"].(map[string]interface{}); ok {
			entry["state"] = map[string]interface{}{
				"operational": state["operational"],
				"link_state":  state["link_state"],
			}
		}
		if addrs, ok := i["addresses"].([]interface{}); ok {
			simplifiedAddrs := make([]map[string]interface{}, 0, len(addrs))
			for _, a := range addrs {
				if am, ok := a.(map[string]interface{}); ok {
					simplifiedAddrs = append(simplifiedAddrs, map[string]interface{}{
						"address": am["address"],
						"family":  am["family"],
						"netmask": am["netmask"],
					})
				}
			}
			entry["addresses"] = simplifiedAddrs
		}
		simplified = append(simplified, entry)
	}

	response := map[string]interface{}{
		"interfaces":     simplified,
		"interface_count": len(simplified),
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleUpdateNetworkInterface(client *truenas.Client, args map[string]interface{}) (string, error) {
	ifaceID, err := resolveInterfaceID(client, args)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{}
	if mtu, ok := args["mtu"].(float64); ok && mtu > 0 {
		payload["mtu"] = int(mtu)
	}
	if enabled, ok := args["enabled"].(bool); ok {
		payload["enabled"] = enabled
	}
	if addrs, ok := args["addresses"].([]interface{}); ok {
		payload["addresses"] = addrs
	}
	if bootPriority, ok := args["boot_priority"].(float64); ok {
		payload["boot_priority"] = int(bootPriority)
	}

	if len(payload) == 0 {
		return "", fmt.Errorf("no fields to update (mtu, enabled, addresses, boot_priority)")
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": "interface.update",
			"iface_id":  ifaceID,
			"payload":   payload,
			"note":      "Preview only. No interface updated.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	result, err := client.Call("interface.update", ifaceID, payload)
	if err != nil {
		return "", fmt.Errorf("failed to update interface: %w", err)
	}

	response := map[string]interface{}{
		"success":  true,
		"iface_id": ifaceID,
		"result":   result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func resolveInterfaceID(client *truenas.Client, args map[string]interface{}) (int64, error) {
	if id, ok := args["iface_id"].(float64); ok && id > 0 {
		return int64(id), nil
	}
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return 0, fmt.Errorf("iface_id or name is required")
	}
	filters := []interface{}{[]interface{}{"name", "=", name}}
	options := map[string]interface{}{"get": true}
	result, err := client.Call("interface.query", filters, options)
	if err != nil {
		return 0, fmt.Errorf("failed to look up interface %s: %w", name, err)
	}
	var iface map[string]interface{}
	if err := json.Unmarshal(result, &iface); err != nil {
		return 0, fmt.Errorf("failed to parse interface lookup: %w", err)
	}
	if iface == nil {
		return 0, fmt.Errorf("interface %s not found", name)
	}
	id, ok := iface["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("interface %s has no id", name)
	}
	return int64(id), nil
}
