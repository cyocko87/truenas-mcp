# Deploying read-only shell access for truenas-mcp

`run_readonly_command` executes commands on the TrueNAS host over SSH.
Enforcement is two-layered:

1. **Client-side**: `tools/shell.go` rejects anything not matching a strict
   read-only allowlist (no pipes, redirects, chaining, substitution, globbing,
   or mutating commands).
2. **Server-side**: `ro-shell.sh` (this directory) re-validates
   `$SSH_ORIGINAL_COMMAND` on the NAS. Even if the MCP tool is bypassed, the
   NAS rejects non-allowlisted commands.

## One-time setup

### 1. Install the wrapper on TrueNAS

The TrueNAS API cannot write arbitrary files, so this is a single manual step.
In the TrueNAS UI (System > Shell) run:

```sh
cat > /usr/local/bin/ro-shell.sh <<'EOF'
# <paste contents of deploy/ro-shell.sh>
EOF
chmod 755 /usr/local/bin/ro-shell.sh
```

Or copy the file via SCP/SSH if the SSH service is already enabled.

### 2. Create a dedicated read-only user

Via the MCP `create_user` tool, or the UI:

- Username: `mcp-ro`
- password_disabled: true (key-only auth)
- Home: `/nonexistent` (or `/var/empty`)
- Groups: add `docker` if `docker *` commands are needed. Without it, docker
  commands will be rejected by the OS (docker socket is root/docker-group).
  Note: docker group is effectively root-equivalent on the host — decide
  whether the convenience is worth it; everything else works unprivileged.
- Shell: try `/usr/local/bin/ro-shell.sh`. If the API/UI rejects a shell not
  in `user.shell_choices`, instead set the SSH public key (next step) with a
  forced-command prefix — see 3b below. (Or use sshd `Match` block, 3c.)

### 3. Authorize the MCP key with a forced command

Generate a dedicated keypair on the MCP host:

```powershell
ssh-keygen -t ed25519 -f C:\Users\jakey\.ssh\truenas_mcp_ro -N '""'
```

Then push the public key to the `mcp-ro` user (the existing `sync_ssh_key`
tool can do this blindly with backend `file` and key_ref pointing at the
`.pub` file). Three ways to bind the wrapper, in order of preference:

a) **Login shell**: set user `shell` = `/usr/local/bin/ro-shell.sh`
   (SSH_ORIGINAL_COMMAND is still set for non-interactive `ssh user@host cmd`).

b) **Forced command in authorized_keys**: if the `sshpubkey` field accepts a
   full authorized_keys line, use:
   `command="/usr/local/bin/ro-shell.sh",no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding ssh-ed25519 AAAA...`

c) **sshd Match block**: Services > SSH > Auxiliary Parameters:
   ```
   Match User mcp-ro
       ForceCommand /usr/local/bin/ro-shell.sh
       AllowAgentForwarding no
       AllowTcpForwarding no
       X11Forwarding no
   ```

Whichever path is used, the key alone must not grant a real shell.

### 4. Enable/start SSH

`control_service` tool: `service=ssh`, `action=start`, then enable it to run
at boot (UI: System > Services). Optionally restrict SSH to LAN via TrueNAS
interface binding or OPNsense firewall rules.

### 5. Configure the MCP

Add env vars to the truenas MCP entry in `mcp_config.json`:

```json
"env": {
  "TRUENAS_API_KEY": "...",
  "TRUENAS_SSH_TARGET": "mcp-ro@192.168.5.5",
  "TRUENAS_SSH_KEY": "C:\\Users\\jakey\\.ssh\\truenas_mcp_ro"
}
```

### 6. Verify

```
run_readonly_command: "docker ps"          -> succeeds
run_readonly_command: "docker stop x"      -> rejected client-side
run_readonly_command: "cat /etc/passwd; id" -> rejected client-side
ssh -i <key> mcp-ro@host "reboot"          -> rejected server-side (ro-shell)
```

## Notes

- Non-interactive SSH has no TTY, so pagers/editors can't be abused.
- All invocations are logged to syslog via `logger -t ro-shell`
  (`grep ro-shell /var/log/messages` or midclt `system.logs`).
- The allowlist intentionally excludes `find`, `grep`, `awk`, `sed` (broad
  read/exec surface) and any command that can write.
- `cat`/`journalctl`/`midclt` can still read sensitive data the OS lets the
  `mcp-ro` user read. Keep `mcp-ro` unprivileged; filesystem permissions are
  the final boundary.
