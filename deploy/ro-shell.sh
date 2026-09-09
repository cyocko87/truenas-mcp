#!/bin/sh
# ro-shell.sh - forced-command wrapper for read-only SSH diagnostics on TrueNAS.
#
# Install as the login shell (or authorized_keys forced command) of the
# dedicated read-only user (e.g. "mcp-ro"). Every SSH command is validated
# against an allowlist before execution; anything else is rejected and logged.
#
# This is the SERVER-SIDE enforcement layer for the truenas-mcp
# run_readonly_command tool. It must be strict even if the client-side
# allowlist is bypassed.

CMD="$SSH_ORIGINAL_COMMAND"
LOG="logger -t ro-shell"

if [ -z "$CMD" ]; then
    echo "ro-shell: interactive login not permitted" >&2
    $LOG "denied: empty command (interactive login attempt)"
    exit 1
fi

# Normalize whitespace.
CMD=$(echo "$CMD" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')

if [ ${#CMD} -gt 512 ]; then
    echo "ro-shell: denied (command too long)" >&2
    $LOG "denied(len): $CMD"
    exit 1
fi

# 1. Deny shell metacharacters: chaining, pipes, redirects, substitution,
#    globbing, history expansion.
if echo "$CMD" | grep -qE '[;&|<>`$(){}\[\]?!#~^*]'; then
    echo "ro-shell: denied (metacharacters)" >&2
    $LOG "denied(meta): $CMD"
    exit 1
fi

# 2. Deny mutating/dangerous words anywhere in the command.
if echo "$CMD" | grep -qiE '\b(add|attach|change|clear|connect|create|delete|del|detach|disable|down|enable|exec|export|flush|import|insert|join|kill|load|mask|new|offline|online|reboot|remove|rename|replace|restart|rollback|rotate|set|shutdown|start|stop|sync|unload|unmask|up|update|upgrade|upload|vacuum|passwd|rm|mv|cp|ln|dd|tee|mkfs|mkswap|fdisk|parted|shred|wipefs|halt|poweroff|useradd|userdel|usermod|groupadd|groupdel|chmod|chown|chattr|truncate|killall|pkill|nsenter|unshare|chroot|su|sudo|doas|screen|tmux|nohup|apt|dpkg|yum|dnf|pacman|pip|pip3|npm|snap|flatpak|perl|ruby|php|python|python3|node|deno|bash|zsh|csh|ksh|fish|ssh|scp|sftp|rsync|nc|ncat|socat|telnet|ftp|tftp|expect)\b'; then
    echo "ro-shell: denied (mutating word)" >&2
    $LOG "denied(word): $CMD"
    exit 1
fi

# 3. Deny dangerous flags on otherwise-allowed commands.
if echo "$CMD" | grep -qiE 'dmesg +.*(--clear|--console|-[a-zA-Z]*[cCnEDr])'; then
    echo "ro-shell: denied (dmesg flag)" >&2; $LOG "denied(flag): $CMD"; exit 1
fi
if echo "$CMD" | grep -qiE 'journalctl +.*( -[a-zA-Z]*f\b|--vacuum|--rotate|--flush|--sync|--header|--update-catalog)'; then
    echo "ro-shell: denied (journalctl flag)" >&2; $LOG "denied(flag): $CMD"; exit 1
fi
if echo "$CMD" | grep -qiE 'smartctl +.*(-[a-zA-Z]*[tso]|--test|--set|--identify)'; then
    echo "ro-shell: denied (smartctl flag)" >&2; $LOG "denied(flag): $CMD"; exit 1
fi
if echo "$CMD" | grep -qiE '(fuser +.*-[a-zA-Z]*k\b|ss +.*-[a-zA-Z]*K\b|tail +.*-[a-zA-Z]*f\b|docker +(logs|events) +.*-[a-zA-Z]*f\b|rpcinfo +.*-[a-zA-Z]*[db])'; then
    echo "ro-shell: denied (dangerous flag)" >&2; $LOG "denied(flag): $CMD"; exit 1
fi
if echo "$CMD" | grep -qiE 'midclt +call +[a-zA-Z0-9_.]+\.(create|update|delete|do_|set_|start|stop|restart|destroy|attach|detach|remove|add|set)'; then
    echo "ro-shell: denied (midclt mutating method)" >&2; $LOG "denied(midclt): $CMD"; exit 1
fi

# 4. Allowlist: first word (+ subcommand where relevant) must be read-only.
ALLOWED=0
case "$CMD" in
    "docker ps"*|\
    "docker inspect"*|\
    "docker logs"*|\
    "docker top"*|\
    "docker images"*|\
    "docker version"|\
    "docker info"|\
    "docker diff"*|\
    "docker port"*|\
    "docker stats --no-stream"*|\
    "docker network ls"*|\
    "docker network inspect"*|\
    "docker volume ls"*|\
    "docker volume inspect"*|\
    "docker compose ls"*|\
    "docker compose ps"*|\
    "docker compose config"*|\
    "docker compose top"*|\
    "docker compose logs"*|\
    "docker system df"|\
    "ls "*|"ls"|\
    "cat "*|\
    "head "*|\
    "tail "*|\
    "stat "*|\
    "file "*|\
    "du "*|"du"|\
    "df"*|\
    "wc "*|\
    "findmnt"*|\
    "realpath "*|\
    "readlink "*|\
    "tree"*|\
    "mount"|\
    "zpool status"*|\
    "zpool list"*|\
    "zpool iostat"*|\
    "zpool get"*|\
    "zpool history"*|\
    "zpool events"|\
    "zfs list"*|\
    "zfs get"*|\
    "zfs diff"*|\
    "zfs holds"*|\
    "zfs userspace"*|\
    "lsblk"*|\
    "blkid"*|\
    "lsscsi"*|\
    "smartctl "*|\
    "nvme list"*|\
    "nvme id-"*|\
    "nvme smart-log"*|\
    "nvme error-log"*|\
    "nvme fw-log"*|\
    "nvme self-test-log"*|\
    "nvme list-ns"*|\
    "nvme list-ctrl"*|\
    "nvme show-regs"*|\
    "nvme get-log"*|\
    "hdparm -i "*|"hdparm -I "*|\
    "arc_summary"*|\
    "arcstat"*|\
    "uptime"|"uname"*|\
    "date"|"who"|"w"|"last"*|\
    "free"*|\
    "vmstat"*|"iostat"*|"mpstat"*|\
    "dmesg"*|\
    "lsmod"*|\
    "lscpu"*|"lshw"*|"lsusb"*|"lspci"*|\
    "dmidecode"*|"sensors"*|\
    "ps"*|\
    "pgrep "*|"pidof "*|\
    "lsof"*|\
    "nproc"|"locale"|"arch"|\
    "printenv"*|"env"|\
    "timedatectl"*|"hostname"|"hostnamectl"*|\
    "lsmem"*|"lsirq"*|"lslocks"*|"lsipc"*|"lsns"*|"lslogins"*|"lsfd"*|\
    "getent"*|\
    "swapon --show"|\
    "top -b"*|\
    "systemctl status"*|\
    "systemctl list-units"*|\
    "systemctl list-unit-files"*|\
    "systemctl list-timers"*|\
    "systemctl is-active"*|\
    "systemctl is-enabled"*|\
    "systemctl is-failed"*|\
    "systemctl cat"*|\
    "systemctl show"*|\
    "systemctl show-environment"|\
    "systemctl list-jobs"|"systemctl list-sockets"|"systemctl list-machines"|\
    "systemctl get-default"|"systemctl list-dependencies"*|\
    "systemctl is-system-running"|\
    "journalctl"*|\
    "ip addr"*|\
    "ip address"*|\
    "ip a"|"ip -4 a"|"ip -6 a"|\
    "ip route"*|\
    "ip r"|"ip -4 r"|"ip -6 r"|\
    "ip link"*|\
    "ip l"|\
    "ip neigh"*|\
    "ip n"|"ip -4 n"|"ip -6 n"|\
    "ip rule"*|\
    "ip maddr"*|\
    "ip mroute"*|\
    "ip netns list"*|\
    "ip vrf show"|\
    "ss "*|"ss"|\
    "netstat"*|"ifconfig"*|"iwconfig"*|"iw"*|\
    "ethtool "*|\
    "mii-tool"*|\
    "arp"*|\
    "bridge link"*|"bridge fdb"*|"bridge mdb"*|"bridge vlan"*|\
    "conntrack -L"*|\
    "nft list"*|\
    "iptables -"*|"ip6tables -"*|\
    "resolvectl status"*|"resolvectl statistics"*|"resolvectl query"*|\
    "resolvectl show-cache"*|"resolvectl dns"*|"resolvectl domain"*|\
    "nslookup "*|"dig "*|"host "*|"whois "*|\
    "ping "*|"ping6 "*|"traceroute "*|"tracepath "*|"arping "*|\
    "curl -sI"*|"curl -s -I"*|\
    "midclt call "*|\
    "smbstatus"*|"nfsstat"*|"nfsiostat"*|\
    "exportfs -s"*|"exportfs -v"*|\
    "showmount -e"*|"rpcinfo -p"*|\
    "iscsiadm -m session"*|"iscsiadm -m discoverydb"*|"iscsiadm -m iface"*|"iscsiadm -m node"*|\
    "k3s kubectl get"*|"k3s kubectl describe"*|"k3s kubectl logs"*|"k3s kubectl top"*|\
    "kubectl get"*|"kubectl describe"*|"kubectl logs"*|"kubectl top"*|\
    "virsh list"*|"virsh dominfo"*|"virsh domstate"*|"virsh domblkstat"*|"virsh domifstat"*|\
    "virsh domstats"*|"virsh dumpxml"*|\
    "virsh nodeinfo"*|"virsh version"*|"virsh capabilities"*|\
    "virsh pool-list"*|"virsh vol-list"*|"virsh net-list"*|"virsh snapshot-list"*|\
    "bootenv"*|"zectl list"*|"zectl get"*|\
    "zpool_influxdb"*)
        ALLOWED=1
        ;;
esac

# midclt: method must end in a read suffix or be explicitly safe.
if [ "$ALLOWED" -eq 1 ]; then
    case "$CMD" in
        "midclt call "*)
            METHOD=$(echo "$CMD" | awk '{print $3}')
            case "$METHOD" in
                *.query|*.config|*.get_instance|*.status|*.info|*.version|*.ready|*.choices|*.stats|*.logs|*.summary|*.capacity|*.targets|*.sessions|\
                core.ping|core.arp|core.get_methods|core.get_services|system.info|system.version|system.product_name|system.is_freenas|system.is_ix_hardware|system.boot_id|system.ready|system.state|failover.licensed|failover.status|interface.has_pending_changes|dns.query|boot.get_state|pool.dataset.encryption_summary)
                    : ;;
                *)
                    ALLOWED=0 ;;
            esac
            ;;
    esac
fi

if [ "$ALLOWED" -ne 1 ]; then
    echo "ro-shell: denied (not allowlisted)" >&2
    $LOG "denied(allowlist): $CMD"
    exit 1
fi

$LOG "allowed: $CMD"
exec /bin/sh -c "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec $CMD"
