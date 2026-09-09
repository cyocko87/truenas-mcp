# Deploying read-only shell access for truenas-mcp

`run_readonly_command` executes commands on the TrueNAS host over SSH.
Enforcement is two-layered:

1. **Client-side**: `tools/shell.go` rejects anything not matching a strict
   read-only allowlist (no pipes, redirects, chaining, substitution, or
   mutating commands).
2. **Server-side**: `ro-shell.sh` (this directory) re-validates
   `$SSH_ORIGINAL_COMMAND` on the NAS. Even if the MCP tool is bypassed, the
   NAS rejects non-allowlisted commands.

## One-time setup

This guide uses datasets on the `apps` pool (`/mnt/apps/utils/mcp`) so the
wrapper and home directory survive reboots. Adjust the pool name if needed.

### 1. Create datasets and install the wrapper

In the TrueNAS UI → System → Shell, run:

```sh
midclt call pool.dataset.create '{"name": "apps/utils/mcp", "type": "FILESYSTEM", "share_type": "APPS"}'
midclt call pool.dataset.create '{"name": "apps/utils/mcp/home", "type": "FILESYSTEM", "share_type": "APPS"}'

mkdir -p /mnt/apps/utils/mcp/home/.ssh
cat > /mnt/apps/utils/mcp/ro-shell.sh <<'EOF'
# <paste the full contents of deploy/ro-shell.sh from this repo>
EOF
chmod 755 /mnt/apps/utils/mcp/ro-shell.sh
```

### 2. Create the read-only user

Use an admin API key or the TrueNAS UI:

- **Username:** `mcp-ro`
- **Full name:** `MCP read-only`
- **Home:** `/mnt/apps/utils/mcp/home`
- **Home create:** off (it is already a dataset)
- **Shell:** `nologin`
- **Password disabled**
- **SSH public key:** paste the contents of `C:\Users\jakey\.ssh\truenas_mcp_ro.pub`
  (the private key must have no passphrase; the key must be a single unquoted
  public-key line, no `command=` prefix — the forced command is applied by sshd
  instead).

Then set ownership and permissions:

```sh
chown -R mcp-ro:mcp-ro /mnt/apps/utils/mcp/home
chmod 755 /mnt/apps/utils/mcp/home
chmod 700 /mnt/apps/utils/mcp/home/.ssh
chmod 600 /mnt/apps/utils/mcp/home/.ssh/authorized_keys
```

If the user creation UI overwrote `authorized_keys`, re-run the `chmod` and make
sure `sshpubkey` is set to the plain public key.

### 3. Force the wrapper via sshd `Match` block

In the TrueNAS UI: **Services > SSH > Auxiliary Parameters**, or via
`midclt` with `ssh.update`:

```sh
cat > /tmp/ssh_options.json <<'EOF'
{"options": "Match User mcp-ro\n    ForceCommand /mnt/apps/utils/mcp/ro-shell.sh\n    AllowAgentForwarding no\n    AllowTcpForwarding no\n    X11Forwarding no\n    PasswordAuthentication no\n"}
EOF
midclt call ssh.update "$(cat /tmp/ssh_options.json)"
midclt call service.restart ssh
```

The `ForceCommand` runs through the user's login shell, so `nologin` would
prevent it. Leave the user's shell as a valid shell if you are not using the
`Match` block, or keep `nologin` and rely on `Match` `ForceCommand` with the
understanding that `nologin` would still break the wrapper.

### 4. Enable/start SSH

`control_service` tool: `service=ssh`, `action=start`, then enable it to run
at boot (UI: System > Services). Optionally restrict SSH to LAN via OPNsense
firewall rules.

### 5. Grant read-only Docker access (optional)

`mcp-ro` cannot be added to the protected `docker` group. Grant it ACL access
to the Docker socket. This is not persistent across Docker restarts or reboots
unless added to an Init/Shutdown script:

```sh
setfacl -m u:mcp-ro:rw /var/run/docker.sock
```

### 6. Configure the MCP

Add env vars to the truenas MCP entry in `mcp_config.json`:

```json
"env": {
  "TRUENAS_API_KEY": "...",
  "TRUENAS_SSH_TARGET": "mcp-ro@192.168.5.5",
  "TRUENAS_SSH_KEY": "C:\\Users\\jakey\\.ssh\\truenas_mcp_ro"
}
```

### 7. Verify

```
run_readonly_command: "uptime"             -> succeeds
run_readonly_command: "docker ps"          -> succeeds (after setfacl)
run_readonly_command: "zpool status"       -> succeeds
run_readonly_command: "docker stop x"      -> rejected client-side
run_readonly_command: "cat /etc/passwd; id" -> rejected client-side
ssh -i <key> mcp-ro@host "reboot"          -> rejected server-side (ro-shell)
```

## Notes

- Non-interactive SSH has no TTY, so pagers/editors can't be abused.
- All invocations are logged to syslog via `logger -t ro-shell`
  (`grep ro-shell /var/log/messages` or `midclt system.logs`).
- The allowlist intentionally excludes `find`, `grep`, `awk`, `sed` (broad
  read/exec surface) and any command that can write.
- `cat`/`journalctl`/`midclt` can still read sensitive data the OS lets the
  `mcp-ro` user read. Keep `mcp-ro` unprivileged; filesystem permissions are
  the final boundary.
