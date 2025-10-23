# Beispielhafte Aufrufe

Befehl	Wirkung
```
./miyagi-backup.sh -c /etc/miyagi.conf	Führt den vollständigen Backup-Prozess aus
./miyagi-backup.sh help	Listet alle verfügbaren Funktionen
./miyagi-backup.sh run_updates	Führt nur Updates lokal aus
./miyagi-backup.sh run_pbs_backup	Führt nur das vzdump-PBS-Backup aus
./miyagi-backup.sh run_maintenance	Nur Wartung (Prune + GC)
./miyagi-backup.sh shutdown_if_requested	Prüft ob Shutdown nötig ist
```

####

#  miyagi-check.sh

Dieses Skript überprüft eine Bash-basierte Konfigurationsdatei für ein Backup-System:

## Funktionen:
-  Validiert alle benötigten Variablen
-  Testet SSH-Verbindungen zu `SOURCEHOST` und optional `PBSHOST`
-  Prüft und installiert bei Bedarf den lokalen SSH-Key (`~/.ssh/id_rsa.pub`)
-  Erkennt unsichere `PermitRootLogin yes` Einstellungen
-  Bietet automatische Umstellung auf `prohibit-password` an

## Nutzung:
```bash
./miyagi-check.sh /pfad/zur/config
```