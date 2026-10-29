# Daemonica – Installation (Entwicklungsstand M1.0)

> **Achtung:** Dies ist ein Entwicklungsstand. Die Anmeldung per Passkey und die
> eigentliche Weboberfläche fehlen noch (siehe `docs/STATUS.md`). Nur auf der Test-VM installieren.

## Voraussetzungen

- Debian oder Ubuntu (LTS) mit systemd, root-Zugang
- Das Paket `daemonica_<version>_<arch>-UNSIGNED-TESTONLY.deb` und die Datei `SHA256SUMS`

## 1. Paket prüfen und installieren

```bash
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./daemonica_0.1.0~dev_amd64-UNSIGNED-TESTONLY.deb
```

Nach der Installation laufen zwei Dienste:

| Dienst | Läuft als | Aufgabe |
|---|---|---|
| `daemonica-helper` | root | Führt privilegierte Aktionen aus, nur über lokale Sockets erreichbar |
| `daemonica-web` | `daemonica-web` (ohne Rechte) | Weboberfläche, zunächst **nur auf 127.0.0.1:8443** (Setup-Modus) |

Prüfen:

```bash
systemctl status daemonica-helper daemonica-web
sudo daemonica-admin status
```

## 2. Ersteinrichtung starten

```bash
sudo daemonica-admin bootstrap
```

Das Programm gibt ein **Einmal-Token** aus (60 Minuten gültig, nur einmal verwendbar).
Wenn du per SSH verbunden bist, schlägt es deine aktuelle IP als freizugebendes Netz vor:

```bash
sudo daemonica-admin bootstrap --allow 203.0.113.7/32
```

Dann auf deinem Rechner einen SSH-Tunnel öffnen und im Browser `https://localhost:8443` aufrufen:

```bash
ssh -L 8443:127.0.0.1:8443 benutzer@server
```

Die Zertifikatswarnung im Setup-Modus ist erwartet (temporäres Zertifikat).

## 3. Notfall-Befehle

| Befehl | Wirkung |
|---|---|
| `sudo daemonica-admin allowlist-reset` | Dashboard nur noch lokal erreichbar (falls du dich ausgesperrt hast) |
| `sudo daemonica-admin audit-verify` | Prüft, ob das Audit-Log manipuliert wurde |
| `sudo daemonica-admin status` | Zustand anzeigen |

## 4. Deinstallation

```bash
sudo apt remove daemonica   # Dienste stoppen, Daten bleiben erhalten
sudo apt purge daemonica    # löscht auch Konten, Passkeys, Konfiguration, Backups, geplante Jobs und das Audit-Log
```

- Ein noch offenes ACME-Fenster (vorübergehende Firewall-Freigabe für Port 80/443) wird in beiden Fällen geschlossen.
- Geplante Jobs (`daemonica-job-*`) laufen nach `remove` weiter und werden erst mit `purge` entfernt.
- Firewall-Regeln mit dem Kommentar `daemonica:…` (z. B. SSH- und Dashboard-Zugang) bleiben bewusst bestehen, damit der Zugang nicht abreißt. Prüfen mit `sudo ufw status numbered`, löschen bei Bedarf von Hand.

## 5. Update und Rollback

Updates erfolgen ausschließlich über `apt` (`sudo apt install ./daemonica_<neue-version>_amd64.deb` bzw. später aus dem Repository). Die Dienste werden dabei neu gestartet; angemeldete Sitzungen müssen sich neu anmelden.

Vor jeder Datenbank-Migration legt der Helper automatisch eine Sicherung an: `/var/lib/daemonica-helper/backups/accounts.db.<Zeitstempel>.bak`.

**Rollback auf eine ältere Version:**

```bash
sudo apt install --allow-downgrades ./daemonica_<alte-version>_amd64.deb
sudo systemctl status daemonica-helper
```

Startet der Helper danach nicht und meldet `database is newer than this release`, hat die neuere Version das Datenbankschema bereits erweitert. Die ältere Version rührt die Datenbank dann absichtlich nicht an. In dem Fall die Sicherung von vor dem Update zurückspielen:

```bash
sudo systemctl stop daemonica-web daemonica-helper
sudo ls -l /var/lib/daemonica-helper/backups/          # jüngste Sicherung vor dem Update wählen
sudo rm -f /var/lib/daemonica-helper/accounts.db-wal /var/lib/daemonica-helper/accounts.db-shm
sudo install -m 0600 -o root -g root /var/lib/daemonica-helper/backups/accounts.db.<Zeitstempel>.bak /var/lib/daemonica-helper/accounts.db
sudo systemctl start daemonica-helper daemonica-web
```

Konten, Passkeys und Sitzungen, die nach dieser Sicherung angelegt wurden, fehlen danach. Das Audit-Log bleibt unverändert.
