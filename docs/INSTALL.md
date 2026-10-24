# Daemonia – Installation (Entwicklungsstand M1.0)

> **Achtung:** Dies ist ein Entwicklungsstand. Die Anmeldung per Passkey und die
> eigentliche Weboberfläche fehlen noch (siehe `docs/STATUS.md`). Nur auf der Test-VM installieren.

## Voraussetzungen

- Debian oder Ubuntu (LTS) mit systemd, root-Zugang
- Das Paket `daemonia_<version>_<arch>-UNSIGNED-TESTONLY.deb` und die Datei `SHA256SUMS`

## 1. Paket prüfen und installieren

```bash
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./daemonia_0.1.0~dev_amd64-UNSIGNED-TESTONLY.deb
```

Nach der Installation laufen zwei Dienste:

| Dienst | Läuft als | Aufgabe |
|---|---|---|
| `daemonia-helper` | root | Führt privilegierte Aktionen aus, nur über lokale Sockets erreichbar |
| `daemonia-web` | `daemonia-web` (ohne Rechte) | Weboberfläche, zunächst **nur auf 127.0.0.1:8443** (Setup-Modus) |

Prüfen:

```bash
systemctl status daemonia-helper daemonia-web
sudo daemonia-admin status
```

## 2. Ersteinrichtung starten

```bash
sudo daemonia-admin bootstrap
```

Das Programm gibt ein **Einmal-Token** aus (60 Minuten gültig, nur einmal verwendbar).
Wenn du per SSH verbunden bist, schlägt es deine aktuelle IP als freizugebendes Netz vor:

```bash
sudo daemonia-admin bootstrap --allow 203.0.113.7/32
```

Dann auf deinem Rechner einen SSH-Tunnel öffnen und im Browser `https://localhost:8443` aufrufen:

```bash
ssh -L 8443:127.0.0.1:8443 benutzer@server
```

Die Zertifikatswarnung im Setup-Modus ist erwartet (temporäres Zertifikat).

## 3. Notfall-Befehle

| Befehl | Wirkung |
|---|---|
| `sudo daemonia-admin allowlist-reset` | Dashboard nur noch lokal erreichbar (falls du dich ausgesperrt hast) |
| `sudo daemonia-admin audit-verify` | Prüft, ob das Audit-Log manipuliert wurde |
| `sudo daemonia-admin status` | Zustand anzeigen |

## 4. Deinstallation

```bash
sudo apt remove daemonia   # Daten bleiben erhalten
sudo apt purge daemonia    # löscht auch Konten, Konfiguration und Audit-Log
```

## 5. Update und Rollback

Updates erfolgen ausschließlich über `apt`. Rollback: älteres `.deb` installieren
(`sudo apt install ./daemonia_<alte-version>.deb`); Datenbank-Backups werden ab
Einführung der Datenbank vor jeder Migration automatisch angelegt.
