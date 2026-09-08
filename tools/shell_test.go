package tools

import (
	"strings"
	"testing"
)

// classify mirrors the validation order in handleRunReadonlyCommand.
func classifyShellCmd(command string) (allowed bool, reason string) {
	command = strings.Join(strings.Fields(command), " ")
	if len(command) > shellCmdMaxLen {
		return false, "too long"
	}
	if shellMetaDeny.MatchString(command) {
		return false, "metachar"
	}
	if shellMutatingWords.MatchString(command) {
		return false, "mutating word"
	}
	for _, re := range shellDangerousFlags {
		if re.MatchString(command) {
			return false, "dangerous flag"
		}
	}
	for _, re := range shellAllowlist {
		if re.MatchString(command) {
			return true, ""
		}
	}
	return false, "not allowlisted"
}

func TestReadOnlyCommandsAllowed(t *testing.T) {
	allowed := []string{
		"docker ps",
		"docker ps -a",
		"docker inspect jellyfin",
		"docker logs --tail 50 jellyfin",
		"docker stats --no-stream",
		"docker network ls",
		"docker network inspect ix-jellyfin_default",
		"docker compose ls",
		"cat /etc/version",
		"ls -la /mnt/tank",
		"df -h",
		"uptime",
		"zpool status",
		"zpool list -v",
		"zfs list -r tank",
		"zfs get all tank/apps",
		"smartctl -a /dev/sda",
		"nvme list",
		"ip addr",
		"ip route show",
		"ss -tlnp",
		"midclt call app.query",
		"midclt call system.info",
		"midclt call pool.dataset.query",
		"systemctl status docker",
		"journalctl -u docker --since today",
		"ps aux",
		"free -h",
		"mount",
		"iptables -L -n",
		"nft list ruleset",
		"virsh list",
		"k3s kubectl get pods -A",
		"sensors",
		"dmidecode",
	}
	for _, c := range allowed {
		if ok, reason := classifyShellCmd(c); !ok {
			t.Errorf("expected allowed: %q (rejected: %s)", c, reason)
		}
	}
}

func TestMutatingCommandsRejected(t *testing.T) {
	rejected := []string{
		// metacharacters / injection
		"cat /etc/passwd; rm -rf /",
		"docker ps && reboot",
		"ls | grep foo",
		"cat /etc/shadow > /tmp/x",
		"echo $(id)",
		"cat `which ls`",
		"docker ps\nreboot",
		"ls /etc/*",
		// mutating commands
		"docker exec jellyfin bash",
		"docker run -it debian bash",
		"docker stop jellyfin",
		"docker rm jellyfin",
		"docker compose up -d",
		"docker system prune",
		"zfs destroy tank/x",
		"zfs create tank/x",
		"zfs mount -a",
		"zpool export tank",
		"zpool scrub tank",
		"zpool clear tank",
		"mount /dev/sda1 /mnt",
		"umount /mnt",
		"rm -rf /tmp/x",
		"shutdown now",
		"systemctl restart ssh",
		"systemctl daemon-reload",
		// dangerous flags on allowed commands
		"ip link set dev eth0 up",
		"ip addr add 10.0.0.1/24 dev eth0",
		"ip route flush",
		"ip netns exec foo id",
		"dmesg -C",
		"dmesg --clear",
		"journalctl --vacuum-time=1d",
		"journalctl -f",
		"smartctl -t short /dev/sda",
		"smartctl -s on /dev/sda",
		"nvme format /dev/nvme0",
		"hdparm -Y /dev/sda",
		"ethtool -s eth0 speed 100",
		"fuser -k /mnt",
		"ss -K",
		"tail -f /var/log/messages",
		"docker logs -f jellyfin",
		// shell escapes / other binaries
		"bash -c id",
		"sh -c id",
		"python3 -c 'print(1)'",
		"sudo ls",
		"nc -l 4444",
		"ssh otherhost",
		"midclt call pool.dataset.create",
		"midclt call service.update",
		"midclt call user.update",
		"kubectl delete pod x",
		"kubectl exec -it pod -- bash",
		// not in allowlist
		"find / -name x",
		"grep -r . /etc",
		"apt-get install x",
		"wget http://x",
	}
	for _, c := range rejected {
		if ok, _ := classifyShellCmd(c); ok {
			t.Errorf("expected rejected but was allowed: %q", c)
		}
	}
}
