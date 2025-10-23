#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

log() {
    echo "[INFO] $*"
}

error_exit() {
    echo "[ERROR] $*" >&2
    exit 1
}

sanitize_value() {
    echo "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

load_config() {
    local config_file="$1"
    if [[ ! -f "$config_file" ]]; then
        error_exit "Konfigurationsdatei nicht gefunden: $config_file"
    fi

    log "Lade und bereinige Konfigurationsdatei: $config_file"
    while IFS='=' read -r key value; do
        # nur gültige Variablennamen parsen
        if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            # Kommentar nach Wert entfernen
            value="${value%%#*}"
            value="$(sanitize_value "$value")"
            # Variable setzen (für den write_new_config Zugriff)
            eval "$key=\"$value\""
        fi
    done < "$config_file"
}

write_new_config() {
    local out_file="$1"

    cat > "$out_file" <<EOF
#Edit all Variables for best Experience

UPDATES='${UPDATES}'         # Proxmox VE und PBS Updates nach dem Lauf
SHUTDOWN='${SHUTDOWN}'       # System nach Ausführung herunterfahren?

# Quelle (Proxmox VE System, das gesichert wird)
SOURCEPORT='${SOURCEPORT}'   # SSH-Port, normalerweise 22
SOURCEHOST='${SOURCEHOST}'   # IP des Quell-Proxmox-Servers

# Replikation (ZFS)
ZFSROOT='${ZFSROOT}'          # Erstes Dataset vom Quellsystem
ZFSSECOND='${ZFSSECOND}'      # Optional zweites Dataset
ZFSTRGT='${ZFSTRGT}'          # Zielpfad für Replikation

# ZFS Zsync Replikation
ZSYNC='${ZSYNC}'               # ZSYNC aktivieren (ja/nein)
ZPUSHTAG='${ZPUSHTAG}'         # Benutzer-Tag für ZFS
ZPUSHMINKEEP='${ZPUSHMINKEEP}' # Mindestens zu behaltende Snapshots
ZPUSHKEEP='${ZPUSHKEEP}'       # Snapshots mit dem Tag, die behalten werden
ZPUSHLABEL='${ZPUSHLABEL}'     # Suffix für Snapshot-Autoengine
ZPUSHFILTER='${ZPUSHFILTER}'   # Weitere Filter (leer lassen oder Muster wie daily| weekly etc.)

# Backup mit Proxmox Backup Server
BACKUPSERVER='${BACKUPSERVER}'     # Backup via PBS aktivieren?
MAINTDAY='${MAINTDAY}'             # Wartungstag (1=Mo, 7=So)
PBSHOST='${PBSHOST}'               # IP des Proxmox Backup Servers
BACKUPSTORE='${BACKUPSTORE}'       # Datastore auf Quell-Proxmox
BACKUPSTOREPBS='${BACKUPSTOREPBS}' # Datastore auf PBS
BACKUPEXCLUDE='${BACKUPEXCLUDE}'   # VM/CT-IDs, die vom Backup ausgeschlossen sind
REPLEXCLUDE=\$BACKUPEXCLUDE        # Diese auch von Replikation ausschließen

# Zusätzliche Monitoring-Ziele 
# External Piggyback Host
EPIGGYBACK='${EPIGGYBACK}'            # Piggyback-Daten an Monitoring-Ziel senden?
EPIGGYBACK_PORT='${EPIGGYBACK_PORT}'  # SSH-Port für EPIGGYBACK_HOST
EPIGGYBACK_HOST='${EPIGGYBACK_HOST}'  # Monitoring-Zielhost für Piggyback

# External Checkzfs Host
ECHECKZFS='${ECHECKZFS}'              # check_zfs-Output an Monitoring-Ziel senden?
ECHECKZFS_PORT='${ECHECKZFS_PORT}'    # SSH-Port für ECHECKZFS_HOST
ECHECKZFS_HOST='${ECHECKZFS_HOST}'    # Monitoring-Zielhost für check_zfs
EOF
}


if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <configfile>"
    exit 1
fi

ORIGINAL="$1"

read -rp "Soll die aktuelle Datei als Backup gesichert werden (umbenennen)? (ja/nein): " RESPONSE
RESPONSE="${RESPONSE,,}"

if [[ "$RESPONSE" == "ja" || "$RESPONSE" == "j" ]]; then
    BACKUPFILE="${ORIGINAL}.bak"
    mv "$ORIGINAL" "$BACKUPFILE"
    log "Originaldatei wurde umbenannt in: $BACKUPFILE"
    CONFIG_TO_READ="$BACKUPFILE"
else
    log "Keine Sicherung der Originaldatei durchgeführt. Original bleibt unverändert."
    CONFIG_TO_READ="$ORIGINAL"
fi

NEWFILE="${ORIGINAL}.convert"
load_config "$CONFIG_TO_READ"
write_new_config "$NEWFILE"
log "Neue Konfiguration geschrieben in: $NEWFILE"
