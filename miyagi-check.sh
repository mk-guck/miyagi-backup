#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

PERMITROOT_YES_HOSTS=()
LOG() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

CONFIG_FILE="${1:-}"

if [[ -z "$CONFIG_FILE" ]]; then
    LOG "Keine Konfigurationsdatei übergeben."
    echo "Usage: $0 /pfad/zur/config"
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    LOG "Konfigurationsdatei nicht gefunden: $CONFIG_FILE"
    exit 1
fi

if ! bash -n "$CONFIG_FILE"; then
    LOG "Syntaxfehler in der Konfigurationsdatei!"
    exit 1
fi

source "$CONFIG_FILE"

REQUIRED_VARS=(
    SOURCEPORT
    BACKUPSERVER
    ZSYNC
    MAINTDAY
    SHUTDOWN
    UPDATES
    SOURCEHOST
    PBSHOST
    BACKUPSTORE
    BACKUPSTOREPBS
    BACKUPEXCLUDE
    REPLEXCLUDE
)

MISSING=()
for var in "${REQUIRED_VARS[@]}"; do
    if ! declare -p "$var" &>/dev/null || [[ -z "${!var}" ]]; then
        MISSING+=("$var")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    LOG " Fehlende Variablen in Konfiguration:"
    for v in "${MISSING[@]}"; do echo " - $v"; done
    exit 1
else
    LOG " Alle Variablen gesetzt."
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    LOG " Fehlende Variablen in Konfiguration:"
    for v in "${MISSING[@]}"; do echo " - $v"; done
    exit 1
else
    LOG " Alle Variablen gesetzt."
fi

# Prüfung, ob SHUTDOWN auch tatsächlich in der Datei definiert wurde
if ! grep -qE '^\s*SHUTDOWN\s*=' "$CONFIG_FILE"; then
    LOG "Hinweis: Die Variable 'SHUTDOWN' ist zwar gesetzt, aber nicht direkt in der Konfigurationsdatei '$CONFIG_FILE' definiert."
    LOG "   → Bitte prüfen, ob dies gewollt ist oder von einer übergeordneten Quelle stammt."
fi

# Anzeigen, ob SHUTDOWN aktiv ist
LOG "SHUTDOWN-Status: ${SHUTDOWN:-nicht gesetzt}"

case "${SHUTDOWN,,}" in
    yes)
        LOG "Nach dem Backup wird das System heruntergefahren."
        ;;
    no)
        LOG "Kein automatischer Shutdown nach dem Backup."
        ;;
    *)
        LOG "Unbekannter SHUTDOWN-Wert: '${SHUTDOWN}' , erwartet: 'yes' oder 'no'"
        ;;
esac

check_ssh_connection() {
    local host=$1
    LOG "Prüfe SSH-Verbindung zu $host ..."
    if ssh -p "$SOURCEPORT" -o BatchMode=yes -o ConnectTimeout=5 "$host" "echo OK" 2>/dev/null | grep -q OK; then
        LOG " SSH-Verbindung zu $host erfolgreich."
        return 0
    else
        LOG " SSH-Verbindung zu $host fehlgeschlagen!"
        return 1
    fi
}

check_and_copy_ssh_key() {
    local host=$1
    local keyfile="$HOME/.ssh/id_rsa.pub"

    if [[ ! -f "$keyfile" ]]; then
        LOG " Lokaler SSH-Public-Key ($keyfile) nicht gefunden!"
        return 1
    fi
    local pubkey
    pubkey=$(<"$keyfile")

    LOG " Prüfe, ob SSH-Key auf $host autorisiert ist ..."

    if ssh -p "$SOURCEPORT" "$host" "grep -qF '$pubkey' ~/.ssh/authorized_keys" 2>/dev/null; then
        LOG " SSH-Key ist bereits auf $host hinterlegt."
    else
        LOG " SSH-Key nicht auf $host vorhanden."

        read -rp " Möchtest du den SSH-Key jetzt via ssh-copy-id übertragen? [j/N] " ans
        if [[ "$ans" =~ ^[JjYy]$ ]]; then
            ssh-copy-id -p "$SOURCEPORT" "$host"
        else
            LOG " SSH-Key nicht übertragen."
        fi
    fi
}

check_sshd_config_recommendation() {
    local host=$1
    LOG " Prüfe sshd_config auf $host bzgl. 'PermitRootLogin'..."

    local current_setting
    current_setting=$(ssh -p "$SOURCEPORT" "$host" "grep -i '^PermitRootLogin' /etc/ssh/sshd_config" 2>/dev/null || echo "")

    if [[ -z "$current_setting" ]]; then
        LOG " Keine explizite 'PermitRootLogin'-Einstellung gefunden."
    elif echo "$current_setting" | grep -qi "PermitRootLogin yes"; then
        LOG " Aktuell ist PermitRootLogin=YES erlaubt auf $host"
        LOG " Empfehlung: auf 'prohibit-password' umstellen."
        PERMITROOT_YES_HOSTS+=("$host")
    else
        LOG " PermitRootLogin-Einstellung ist: $current_setting"
    fi
}

check_pveversion() {
    local host=$1
    LOG "Prüfe PVE-Version auf $host ..."
    if ssh -p "$SOURCEPORT" "$host" "command -v pveversion >/dev/null"; then
        ssh -p "$SOURCEPORT" "$host" "pveversion" | while read -r line; do
            LOG " $host: $line"
        done
    else
        LOG " 'pveversion' ist auf $host nicht verfügbar – kein Proxmox?"
    fi
}
check_pbs_version() {
    local host=$1
    local port=$2
    LOG "Prüfe PBS-Version auf $host ..."
    if ssh -p "$port" "$host" "command -v proxmox-backup-manager >/dev/null"; then
        ssh -p "$port" "$host" "proxmox-backup-manager version" | while read -r line; do
            LOG " $host: $line"
        done
    else
        LOG " 'proxmox-backup-manager' ist auf $host nicht verfügbar – kein PBS?"
    fi
}
run_host_check() {
    local host=$1
    local type=${2:-pve}
    local port=$SOURCEPORT
    local pbsport=$PBSPORT

    LOG ""
    LOG "=== Prüfung für Host: $host (Typ: $type) ==="

    if check_ssh_connection "$host" "$port"; then
        check_and_copy_ssh_key "$host"
        check_sshd_config_recommendation "$host"

        if [[ "$type" == "pve" ]]; then
            check_pveversion "$host" "$port"
        elif [[ "$type" == "pbs" ]]; then
            check_pbs_version "$host" "$pbsport"
        else
            LOG " Unbekannter Host-Typ: $type"
        fi
    fi
    echo ""
}



run_host_check "$SOURCEHOST" pve

if [[ "$BACKUPSERVER" == "yes" ]]; then
    run_host_check "$PBSHOST" pbs
else
    LOG " BACKUPSERVER ist deaktiviert PBSHOST wird übersprungen."
fi

# NACHLAUF: Frage zur automatischen Änderung von PermitRootLogin
if [[ ${#PERMITROOT_YES_HOSTS[@]} -gt 0 ]]; then
    echo ""
    echo " Die folgenden Hosts erlauben derzeit root-Login per Passwort:"
    for h in "${PERMITROOT_YES_HOSTS[@]}"; do
        echo " - $h"
    done

    read -rp " Möchtest du PermitRootLogin auf diesen Hosts auf 'prohibit-password' setzen und sshd neustarten? [j/N] " change_ans
    if [[ "$change_ans" =~ ^[JjYy]$ ]]; then
        for h in "${PERMITROOT_YES_HOSTS[@]}"; do
            echo "Ändere sshd_config auf $h ..."
            ssh -p "$SOURCEPORT" "$h" "sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && systemctl reload sshd && echo '✅ sshd auf $h neu geladen.' || echo '❌ Fehler bei $h'"
        done
    else
        echo "  Änderung von sshd_config übersprungen."
    fi
fi