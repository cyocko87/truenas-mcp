package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/truenas/truenas-mcp/truenas"
)

// run_readonly_command executes a read-only diagnostic command on the TrueNAS
// host over SSH. This is intentionally OUTSIDE the websocket API (which has no
// generic exec method) and is hardened in two layers:
//
//   1. Client-side (this file): a strict allowlist of command patterns, a
//      metacharacter denylist, a mutating-word denylist, and a dangerous-flag
//      denylist. No pipes, redirection, substitution, or chaining permitted.
//   2. Server-side: the SSH account on TrueNAS is expected to have its login
//      shell set to a forced-command wrapper (deploy/ro-shell.sh) that applies
//      its own allowlist to $SSH_ORIGINAL_COMMAND. Even if this client-side
//      check is bypassed, the NAS rejects anything not allowlisted.
//
// Configuration (environment variables read at call time):
//   TRUENAS_SSH_TARGET - required, e.g. "mcp-ro@192.168.5.5"
//   TRUENAS_SSH_KEY    - required, absolute path to the SSH private key
//   TRUENAS_SSH_PORT   - optional, default 22
//
// The private key path is used only as an ssh -i argument and is never
// returned in output.

const (
	shellCmdMaxLen = 512
	shellTimeout   = 30 * time.Second
)

// shellMetaDeny rejects any shell metacharacter that could chain, pipe,
// redirect, substitute, or glob. Includes newlines/carriage returns.
var shellMetaDeny = regexp.MustCompile("[;&|<>\\`$(){}\\[\\]\n\r!#*?~^]")

// shellMutatingWords rejects commands containing words that imply mutation,
// even as arguments (e.g. "ip link set dev eth0 up").
var shellMutatingWords = regexp.MustCompile(`(?i)\b(` +
	`add|attach|change|clear|connect|create|delete|del|detach|disable|down|` +
	`enable|exec|export|flush|import|insert|join|kill|load|mask|new|` +
	`offline|online|reboot|remove|rename|replace|restart|rollback|rotate|set|` +
	`shutdown|start|stop|sync|unload|unmask|up|update|upgrade|upload|vacuum|` +
	`passwd|rm|mv|cp|ln|dd|tee|mkfs|mkswap|fdisk|parted|shred|wipefs|halt|` +
	`poweroff|useradd|userdel|usermod|groupadd|groupdel|chmod|chown|chattr|` +
	`truncate|killall|pkill|nsenter|unshare|chroot|su|sudo|doas|screen|tmux|` +
	`nohup|apt|dpkg|yum|dnf|pacman|pip|pip3|npm|snap|flatpak|perl|ruby|php|` +
	`python|python3|node|deno|bash|zsh|csh|ksh|fish|ssh|scp|sftp|rsync|nc|` +
	`ncat|socat|telnet|ftp|tftp|expect` +
	`)\b`)

// shellDangerousFlags rejects risky flags on commands whose subcommand-based
// allowlist patterns cannot fully constrain them.
var shellDangerousFlags = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bdmesg\s+.*(--clear|--console|-\w*[cCnEDr]\w*)`),                           // -c/-C clear buffer, -D/-E disable/enable logging
	regexp.MustCompile(`(?i)\bjournalctl\b.*\s-\w*f\b`),                                                 // -f follows forever
	regexp.MustCompile(`(?i)\bjournalctl\b.*--(vacuum|rotate|flush|sync|header|update-catalog)[\w=-]*`), // mutating long flags
	regexp.MustCompile(`(?i)\bsmartctl\s+.*(-\w*[tso]\w*|--test|--set|--identify)`),                     // -t starts tests, -s toggles, -o offline
	regexp.MustCompile(`(?i)\bfuser\s+.*-\w*k\b`),                                                       // -k kills processes
	regexp.MustCompile(`(?i)\bss\s+.*-\w*K\b`),                                                          // -K forcibly closes sockets
	regexp.MustCompile(`(?i)\brpcinfo\s+.*-\w*[db]\w*`),                                                 // -d/-b broadcast/de-register
	regexp.MustCompile(`(?i)\btail\s+.*-\w*f\b`),                                                        // tail -f hangs
	regexp.MustCompile(`(?i)\bdocker\s+(logs|events)\s+.*-\w*f\b`),                                      // docker logs -f / events hang
	regexp.MustCompile(`(?i)\bzpool\s+events\s+.*-v\b`),                                                 // zpool events -v follows

}

// shellAllowlist: broad read-only diagnostics. Every pattern is anchored.
// Argument character classes intentionally exclude all metacharacters.
var shellAllowlist = []*regexp.Regexp{
	// docker / containers (read-only subcommands only)
	regexp.MustCompile(`^docker\s+(ps|inspect|logs|top|images|version|info|port|diff)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^docker\s+stats\s+--no-stream(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^docker\s+(network|volume)\s+(ls|inspect)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^docker\s+compose\s+(ls|ps|config|top|logs)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^docker\s+system\s+df\s*$`),

	// filesystem / text viewing (no find/grep - too broad a surface)
	regexp.MustCompile(`^(ls|cat|head|tail|stat|file|du|df|wc|findmnt|realpath|readlink|tree)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^mount\s*$`),

	// ZFS / storage (read-only subcommands only)
	regexp.MustCompile(`^zpool\s+(status|list|iostat|get|history|capacity)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^zpool\s+events\s*$`),
	regexp.MustCompile(`^zfs\s+(list|get|diff|holds|userspace)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^(lsblk|blkid|lsscsi)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^smartctl(\s+(-[iaxHA]+|--(info|all|xall|health|attributes)|-d\s+\w+|-l\s+(selftest|error|devstat|ssd|env|health|xerror|sataphy|sasphy)|-n\s+\w+|/dev/[\w.]+))+\s*$`),
	regexp.MustCompile(`^nvme\s+(list|list-ns|list-ctrl|id-ctrl|id-ns|smart-log|error-log|fw-log|self-test-log|show-regs|get-log|netapp-smdevices|version)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^hdparm\s+(-i|-I|--verbose)\s+/dev/[\w.]+\s*$`),
	regexp.MustCompile(`^(arc_summary|arcstat)(\s+[\w\-:./=@,+]+)*\s*$`),

	// system state / processes
	regexp.MustCompile(`^(uptime|uname|date|who|w|last|free|vmstat|iostat|mpstat|lsmod|lscpu|lshw|lsusb|lspci|dmidecode|sensors|ps|pgrep|pidof|lsof|nproc|locale|timedatectl|hostname|hostnamectl|arch|printenv|numastat|slabtop\s+-o|lsmem|lsirq|procinfo|swapon\s+--show|lslocks|lsipc|lsns|lslogins|lsfd|getent)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^dmesg(\s+(-[HTxkewl]+|--(human|kernel|userspace|decode|nopager|raw|reltime|ctime|iso|json|level=[\w,]+|facility=[\w,]+|since\s+[\w:.-]+|until\s+[\w:.-]+)))*\s*$`),
	regexp.MustCompile(`^top\s+-b(\s+-n\s+\d+)?(\s+-d\s+\d+)?\s*$`),
	regexp.MustCompile(`^env\s*$`),

	// systemd / logs (read-only subcommands only; -f guarded above)
	regexp.MustCompile(`^systemctl\s+(status|list-units|list-unit-files|list-timers|is-active|is-enabled|is-failed|cat|show|show-environment|list-jobs|list-sockets|list-machines|get-default|list-dependencies|is-system-running)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^journalctl(\s+[\w\-:./=@,+]+)*\s*$`),

	// network: explicit read-only object+verb forms only
	regexp.MustCompile(`^ip\s+(-[46sbrjd]+\s+)*(addr|route|link|neigh|rule|maddr|mroute|tuntap|tcp_metrics|netconf|ntable|token)(\s+(show|list|dump|help|flush help))?(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^ip\s+(-[46sbrjd]+\s+)*(netns\s+(list|identify|monitor)|vrf\s+show)\s*$`),
	regexp.MustCompile(`^ss\s+(-[Hhtuanlpwx4eimro6sS]+(\s+|\b))+[\w\-:./=@,+ ]*$`),
	regexp.MustCompile(`^(netstat|ifconfig|iwconfig|iw|ethtool\s+(-[ikgcP]\s+)?[a-zA-Z][\w.\-]*|mii-tool(\s+-v)?|arp|bridge\s+(link|fdb|mdb|vlan|stplib)|conntrack\s+-L|nft\s+list\s+[\w ]*|iptables(-legacy|-nft)?\s+(-[LS][\w ]*|-t\s+\w+\s+-[LS][\w ]*)|ip6tables(-legacy|-nft)?\s+(-[LS][\w ]*|-t\s+\w+\s+-[LS][\w ]*))(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^(resolvectl|systemd-resolve)\s+(status|statistics|query|show-cache|dns|domain|llmnr|mdns|nta|is-default-route|stub)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^(nslookup|dig|host|whois)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^(ping|ping6|traceroute|traceroute6|tracepath|mtr\s+--report|arping)\s+(-\w+\s+)*[\w\-:./]+(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^curl\s+(-[sSI]|-sI|-s\s+-I)\s+[\w\-:./?=&%+]+\s*$`),

	// sharing / service state
	regexp.MustCompile(`^(smbstatus|nfsstat|nfsiostat|exportfs\s+-s|exportfs\s+-v|showmount\s+-e|rpcinfo\s+-p|iscsiadm\s+-m\s+(session|discoverydb|iface|node)\b)(\s+[\w\-:./=@,+]+)*\s*$`),

	// kubernetes (TrueNAS apps pre-Electric Eel; harmless if k3s absent)
	regexp.MustCompile(`^(k3s\s+)?kubectl\s+(get|describe|logs|top|api-resources|api-versions|version|cluster-info|config\s+view|config\s+current-context)(\s+[\w\-:./=@,+]+)*\s*$`),

	// TrueNAS / misc read-only
	regexp.MustCompile(`^virsh\s+(list|dominfo|domstate|domblkstat|domifstat|domstats|dumpxml|nodeinfo|version|capabilities|pool-list|vol-list|net-list|snapshot-list)(\s+[\w\-:./=@,+]+)*\s*$`),
	regexp.MustCompile(`^(zpool_influxdb|bootenv|zectl\s+(list|get)|truenas-verify)(\s+[\w\-:./=@,+]+)*\s*$`),
}

func handleRunReadonlyCommand(client *truenas.Client, args map[string]interface{}) (string, error) {
	command, ok := args["command"].(string)
	if !ok || strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("command is required")
	}
	command = strings.Join(strings.Fields(command), " ") // normalize whitespace

	if len(command) > shellCmdMaxLen {
		return "", fmt.Errorf("command exceeds %d characters", shellCmdMaxLen)
	}
	if shellMetaDeny.MatchString(command) {
		return "", fmt.Errorf("command rejected: shell metacharacters (pipes, redirects, chaining, substitution, globbing) are not permitted")
	}
	if shellMutatingWords.MatchString(command) {
		return "", fmt.Errorf("command rejected: contains a mutating or non-read-only word")
	}
	for _, re := range shellDangerousFlags {
		if re.MatchString(command) {
			return "", fmt.Errorf("command rejected: contains a dangerous flag")
		}
	}

	allowed := false
	for _, re := range shellAllowlist {
		if re.MatchString(command) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("command not in read-only allowlist: %q", command)
	}

	target := os.Getenv("TRUENAS_SSH_TARGET") // e.g. mcp-ro@192.168.5.5
	keyPath := os.Getenv("TRUENAS_SSH_KEY")
	if target == "" || keyPath == "" {
		return "", fmt.Errorf("shell access not configured: set TRUENAS_SSH_TARGET and TRUENAS_SSH_KEY environment variables")
	}
	port := os.Getenv("TRUENAS_SSH_PORT")
	if port == "" {
		port = "22"
	}

	sshArgs := []string{
		"-i", keyPath,
		"-p", port,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=accept-new",
		target,
		"--",
		command,
	}

	ctx, cancel := context.WithTimeout(context.Background(), shellTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", sshArgs...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if len(output) > 20000 {
		output = output[:20000] + "\n... (truncated at 20000 chars)"
	}

	response := map[string]interface{}{
		"command":   command,
		"exit_code": 0,
		"output":    output,
	}
	if ctx.Err() == context.DeadlineExceeded {
		response["error"] = "command timed out after 30s"
		response["exit_code"] = -1
	} else if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			response["exit_code"] = exitErr.ExitCode()
		}
		response["error"] = err.Error()
	}

	formatted, merr := json.MarshalIndent(response, "", "  ")
	if merr != nil {
		return "", merr
	}
	return string(formatted), nil
}
