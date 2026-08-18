package tools

import (
	"encoding/json"
	"fmt"

	"github.com/truenas/truenas-mcp/truenas"
)

func handleQueryServices(client *truenas.Client, args map[string]interface{}) (string, error) {
	filters := []interface{}{}
	if service, ok := args["service"].(string); ok && service != "" {
		filters = append(filters, []interface{}{"service", "=", service})
	}

	options := map[string]interface{}{}
	if orderBy, ok := args["order_by"].(string); ok && orderBy != "" {
		options["order_by"] = []interface{}{orderBy}
	} else {
		options["order_by"] = []interface{}{"service"}
	}

	result, err := client.Call("service.query", filters, options)
	if err != nil {
		return "", err
	}

	var services []map[string]interface{}
	if err := json.Unmarshal(result, &services); err != nil {
		return "", fmt.Errorf("failed to parse services: %w", err)
	}

	simplified := make([]map[string]interface{}, 0, len(services))
	for _, s := range services {
		simplified = append(simplified, map[string]interface{}{
			"service": s["service"],
			"enable":  s["enable"],
			"state":   s["state"],
			"running": s["running"],
		})
	}

	response := map[string]interface{}{
		"services":      simplified,
		"service_count": len(simplified),
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}

func handleControlService(client *truenas.Client, args map[string]interface{}) (string, error) {
	service, ok := args["service"].(string)
	if !ok || service == "" {
		return "", fmt.Errorf("service is required (e.g. ssh, smb, nfs, afp, iscsi)")
	}

	action, ok := args["action"].(string)
	if !ok || action == "" {
		return "", fmt.Errorf("action is required: start, stop, restart, or reload")
	}

	validActions := map[string]bool{"start": true, "stop": true, "restart": true, "reload": true}
	if !validActions[action] {
		return "", fmt.Errorf("action must be start, stop, restart, or reload (got: %s)", action)
	}

	if dryRun, ok := args["dry_run"].(bool); ok && dryRun {
		preview := map[string]interface{}{
			"dry_run":   true,
			"operation": fmt.Sprintf("service.%s", action),
			"service":   service,
			"note":      "Preview only. No service state change.",
		}
		formatted, err := json.MarshalIndent(preview, "", "  ")
		if err != nil {
			return "", err
		}
		return string(formatted), nil
	}

	method := fmt.Sprintf("service.%s", action)
	result, err := client.Call(method, service)
	if err != nil {
		return "", fmt.Errorf("failed to %s service %s: %w", action, service, err)
	}

	response := map[string]interface{}{
		"success": true,
		"service": service,
		"action":  action,
		"result":  result,
	}
	formatted, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", err
	}
	return string(formatted), nil
}
