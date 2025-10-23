#!/bin/bash
# Author: (C) 2025 Patrick Perlbach <patrick@perlbach24.de>
# --- Konfiguration und Initiale Variablen ---
FORCE_YES=0
DRY_RUN=0
CONFIG_FILE=""

# --- Hilfsfunktionen ---
usage() {
  cat <<EOF
Usage: $0 -c <config> [--yes] [--dry-run]

  -c <file>   Pfad zur Konfigurationsdatei (Pflicht)
  --yes       Automatische Ausführung ohne Rückfrage
  --dry-run   Zeigt nur, was gemacht würde
  --help      Diese Hilfe anzeigen
EOF
  exit 1
}

run_or_echo() {
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY-RUN] $*"
  else
    eval "$@"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -c) CONFIG_FILE="$2"; shift 2 ;;
      --yes) FORCE_YES=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --help) usage ;;
      *) echo "[ERROR] Unbekannter Parameter: $1"; usage ;;
    esac
  done

  [[ -z "$CONFIG_FILE" || ! -f "$CONFIG_FILE" ]] && {
    echo "[ERROR] Konfigurationsdatei fehlt oder ungültig!"
    exit 1
  }

  source "$CONFIG_FILE"
}

confirm() {
  if [[ "$FORCE_YES" -eq 1 ]]; then
    return 0
  fi

  while true; do
    read -rp "$1 [j/N]: " yn
    case $yn in
      [JjYy]*) return 0 ;;
      [Nn]*|"") return 1 ;;
      *) echo "Bitte j (ja) oder n (nein) eingeben." ;;
    esac
  done
}


install_cmk() {
  echo "[INFO] Lade cmk.deb herunter..."
  run_or_echo "curl -fsSL \"$CMK_URL\" -o \"$CMK_FILE\""

  echo "[INFO] Installiere cmk.deb..."
  run_or_echo "sudo apt install -y \"$CMK_FILE\""
}

install_fix_interface_names() {
  echo "[INFO] Installiere Fix für Interface-Namen..."
  run_or_echo "wget -O /tmp/debian-fix-interface-names.sh \"$FIX_INTERFACE_NAMES_URL\""
  run_or_echo "chmod +x /tmp/debian-fix-interface-names.sh"
  run_or_echo "bash /tmp/debian-fix-interface-names.sh"
}

install_miyagi_scripts() {
  echo "[INFO] Lade Miyagi-Backup-Skripte..."
  run_or_echo "wget -O miyagi-backup.sh \"$MIYAGI_BACKUP_URL\""
  run_or_echo "wget -O miyagi-check.sh \"$MIYAGI_CHECK_URL\""
  run_or_echo "wget -O miyagi-convert.sh \"$MIYAGI_CONVERT_URL\""
  run_or_echo "mkdir -p /root/miyagi-backup"
  run_or_echo "mv miyagi-backup.sh miyagi-check.sh miyagi-convert.sh /root/miyagi-backup/"
  run_or_echo "chmod +x /root/miyagi-backup/*.sh"
}

install_checkmk_plugins() {
  echo "[INFO] Installiere disk_smart_info Plugin..."
  run_or_echo "curl -fsSL \"$DISK_SMART_INFO_URL\" -o /usr/lib/check_mk_agent/plugins/disk_smart_info"
  run_or_echo "chmod +x /usr/lib/check_mk_agent/plugins/disk_smart_info"
}

install_cleansnaps() {
  echo "[INFO] Installiere cleansnaps Skript..."
  run_or_echo "wget -O /usr/local/bin/cleansnaps \"$CLEANSNAPS_URL\""
  run_or_echo "chmod +x /usr/local/bin/cleansnaps"
}

install_check_snapshot_age() {
  echo "[INFO] Installiere check-snapshot-age..."
  run_or_echo "wget -O /usr/local/bin/check-snapshot-age \"$CHECK_SNAPSHOT_AGE_URL\""
  run_or_echo "chmod +x /usr/local/bin/check-snapshot-age"
}

install_checkzfs() {
  echo "[INFO] Installiere checkzfs..."
  run_or_echo "wget -O /usr/local/bin/checkzfs \"$CHECKZFS_URL\""
  run_or_echo "chmod +x /usr/local/bin/checkzfs"
}

check_ssh() {
  echo "[INFO] Teste SSH-Verbindung zu $SOURCEHOST ..."

  if ssh -p "$SOURCEPORT" -o BatchMode=yes -o ConnectTimeout=5 root@"$SOURCEHOST" "echo Verbindung erfolgreich" 2>/dev/null; then
    echo "[OK] SSH-Verbindung über Schlüssel funktioniert."
  else
    echo "[WARN] Keine Schlüsselbasierte SSH-Verbindung möglich oder abgelehnt."

    echo "[HINWEIS] Eine Passwortabfrage erfolgt jetzt – dies ist normal."
    if ssh -p "$SOURCEPORT" root@"$SOURCEHOST" "echo Verbindung erfolgreich"; then
      echo "[OK] SSH-Verbindung per Passwort erfolgreich."

      if confirm "Möchtest du den lokalen SSH-Schlüssel auf $SOURCEHOST kopieren (per ssh-copy-id)?"; then
        run_or_echo "ssh-copy-id -p \"$SOURCEPORT\" root@\"$SOURCEHOST\""
        echo "[INFO] Bitte erneut starten, um die Schlüsselverbindung zu nutzen."
        exit 0
      else
        echo "[HINWEIS] Es wird weiterhin Passwortabfrage benötigt."
      fi
    else
      echo "[FEHLER] SSH-Verbindung nicht möglich – bitte Zugang prüfen!"
      exit 1
    fi
  fi
}

select_zfs_pools() {
  echo "[INFO] Lade ZFS-Datasets vom Remote-Host..."

  LOCAL_HOSTNAME=$(hostname -s)
  REMOTE_HOSTNAME=$(ssh -p "$SOURCEPORT" root@"$SOURCEHOST" "hostname -s")
  TAG_KEY="bashclub:miyagi-${REMOTE_HOSTNAME}-${LOCAL_HOSTNAME}"
  TAG_VALUE="subvols"

  # Hole alle relevanten Pool-Namen
  mapfile -t pools < <(ssh -p "$SOURCEPORT" root@"$SOURCEHOST" \
    "zfs list -H -o name" | \
    grep -E '/(vm|subvol)-' | \
    grep -viE 'repl|replica' | \
    sed 's:/[^/]*$::' | \
    sort -u)

  if [[ ${#pools[@]} -eq 0 ]]; then
    echo "[WARN] Keine geeigneten Datasets gefunden!"
    return
  fi

  local options=()
  local tagged_pools=()

  for pool in "${pools[@]}"; do
    local tag status
    tag=$(ssh -p "$SOURCEPORT" root@"$SOURCEHOST" zfs get -H -o value "$TAG_KEY" "$pool" 2>/dev/null)
    if [[ "$tag" == "$TAG_VALUE" ]]; then
      status="on"
      tagged_pools+=("$pool")
    else
      status="off"
    fi
    options+=("$pool" "$([[ "$status" == "on" ]] && echo 'TAGGED' || echo 'untagged')" "$status")
  done

  local selected
  selected=$(whiptail --title "ZFS Pools auswählen" \
    --checklist "Wähle Datasets zum Taggen aus:" 20 78 12 \
    "${options[@]}" \
    3>&1 1>&2 2>&3)

  if [[ $? -ne 0 ]]; then
    echo "[INFO] Auswahl abgebrochen."
    return
  fi

  local selected_array=()
  eval "selected_array=($selected)"

  echo "[INFO] Verarbeite Tagging für ausgewählte Pools:"

  for ((i = 0; i < ${#options[@]}; i += 3)); do
    local pool="${options[i]}"
    local prev_status="${options[i+2]}"
    local is_selected=0

    for sel in "${selected_array[@]}"; do
      if [[ "$sel" == "$pool" ]]; then
        is_selected=1
        break
      fi
    done

    if [[ "$is_selected" -eq 1 && "$prev_status" == "off" ]]; then
      echo " → Tagge $pool"
      run_or_echo ssh -p "$SOURCEPORT" root@"$SOURCEHOST" zfs set "$TAG_KEY=$TAG_VALUE" "$pool"
    elif [[ "$is_selected" -eq 0 && "$prev_status" == "on" ]]; then
      echo " → Entferne Tag von $pool"
      run_or_echo ssh -p "$SOURCEPORT" root@"$SOURCEHOST" zfs inherit "$TAG_KEY" "$pool"
    fi
  done
}

main() {
  # URLs und Dateipfade als Variablen, ggf. in Kopfbereich auslagern
  CMK_URL="https://nc.sysops.de/index.php/s/YofRT5LBfX5ZDQs/download/cmk.deb"
  CMK_FILE="/tmp/cmk.deb"

  FIX_INTERFACE_NAMES_URL="https://raw.githubusercontent.com/bashclub/trmm-scripts/refs/heads/main/debian-fix-interface-names.sh"

  MIYAGI_BACKUP_URL="https://gitea.perlbach24.de/scripte/miyagi-backup/raw/branch/main/miyagi-backup.sh"
  MIYAGI_CHECK_URL="https://gitea.perlbach24.de/scripte/miyagi-backup/raw/branch/main/miyagi-check.sh"
  MIYAGI_CONVERT_URL="https://gitea.perlbach24.de/scripte/miyagi-backup/raw/branch/main/miyagi-convert.sh"

  DISK_SMART_INFO_URL="https://raw.githubusercontent.com/bashclub/checkmk-smart/main/disk_smart_info.py"

  CLEANSNAPS_URL="https://raw.githubusercontent.com/bashclub/zfs-housekeeping/refs/heads/main/cleansnaps.sh"

  CHECK_SNAPSHOT_AGE_URL="https://gitea.perlbach24.de/scripte/check-zfs-replication/raw/branch/main/check-snapshot-age"

  CHECKZFS_URL="https://gitea.perlbach24.de/scripte/check-zfs-replication/raw/branch/main/checkzfs.py"

  echo "[INFO] Starte Installation mit Konfig: $CONFIG_FILE"

  install_cmk

  install_fix_interface_names

  install_miyagi_scripts

  install_checkmk_plugins

  install_cleansnaps

  install_check_snapshot_age

  install_checkzfs
  check_ssh
  select_zfs_pools

  echo "[OK] Installation abgeschlossen."
}

# Start
parse_args "$@"
main
