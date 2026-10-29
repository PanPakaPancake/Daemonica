# Abnahme Phase 1 – Checkliste

Diese Checkliste führt durch die Abnahme von Phase 1 (SPEC §6.6): von der frisch
installierten VM über Einrichtung, alle Module und Rollen bis zu Update, Rollback und
Deinstallation. Sie ist für dich als Auftraggeber geschrieben und braucht keine
Entwicklerkenntnisse.

- **Paket:** `daemonica_0.1.0~rc1_amd64-UNSIGNED-TESTONLY.deb` mit `SHA256SUMS`
  (Release Candidate, nicht signiert, nur für Test-Systeme)
- **Begleitend:** `docs/INSTALL.md` (Installation, Notfall-Befehle, Update/Rollback),
  `docs/acceptance/TEST-REPORT-PHASE-1.md` (automatische Tests mit Zahlen),
  `docs/security/AUDIT-PHASE-1.md` (Sicherheitsaudit)
- **Zeitbedarf:** etwa zwei bis drei Stunden
- **Ergebnis je Schritt:** abhaken (☐ → ☑) oder die Abweichung notieren. Eine Abweichung
  heißt nicht, dass du abbrechen musst: notiere sie und mach weiter.

Am Ende entscheidest du: „Phase 1 abgenommen“ oder eine Liste der Punkte, die noch fehlen.
Bis dahin ruht die Arbeit an Phase 2.

Platzhalter in den Befehlen: `<VM-IP>` (öffentliche IP der VM), `<DEINE-IP>` (deine
öffentliche IP, z. B. von https://ifconfig.me), `<DOMAIN>` = `daemonica.404squad.cloud`.

---

## 0. Vorbereitung

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 0.1 | Bei Hostinger die VM mit **Ubuntu 24.04 LTS** neu installieren (Root-Zugang per SSH-Schlüssel). | Leeres System, SSH als root funktioniert. | ☐ |
| 0.2 | DNS prüfen: `<DOMAIN>` zeigt als A-Eintrag auf `<VM-IP>` (`nslookup <DOMAIN>`). | Antwort ist `<VM-IP>`. | ☐ |
| 0.3 | Auf der VM drei normale Linux-Benutzer anlegen: `adduser pancake`, `adduser op`, `adduser leser`. | Benutzer mit UID ≥ 1000. | ☐ |
| 0.4 | Firewall wie im Betrieb: `ufw allow 22/tcp && ufw allow from <DEINE-IP> to any port 8443 proto tcp && ufw enable`. | `ufw status` zeigt die Regeln, SSH bleibt verbunden. | ☐ |
| 0.5 | Snapshot bei Hostinger anlegen („vor Daemonica“). | Snapshot vorhanden. Er wird für die Netzwerk-, Firewall- und fstab-Tests gebraucht. | ☐ |
| 0.6 | Zweites Gerät mit Passkey-Unterstützung bereitlegen (z. B. Handy) und ein zweites Browser-Profil oder ein privates Fenster für die Rollen-Tests. | – | ☐ |

## 1. Installation

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 1.1 | `.deb` und `SHA256SUMS` auf die VM kopieren, dann `sha256sum -c SHA256SUMS --ignore-missing`. | `OK` für das Paket. | ☐ |
| 1.2 | `apt install ./daemonica_0.1.0~rc1_amd64-UNSIGNED-TESTONLY.deb` | Installation ohne Fehler. | ☐ |
| 1.3 | `systemctl status daemonica-helper daemonica-web` | Beide `active (running)`. | ☐ |
| 1.4 | `ss -ltnp \| grep 8443` | Lauscht nur auf `127.0.0.1:8443` (Setup-Modus). | ☐ |
| 1.5 | Von deinem Rechner `https://<VM-IP>:8443` aufrufen. | Keine Verbindung. | ☐ |
| 1.6 | `daemonica-admin status` | Setup nicht abgeschlossen, keine Konten. | ☐ |

## 2. Ersteinrichtung

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 2.1 | `daemonica-admin bootstrap --allow <DEINE-IP>/32` | Einmal-Token, 60 Minuten gültig. | ☐ |
| 2.2 | Auf deinem Rechner `ssh -L 8443:127.0.0.1:8443 root@<VM-IP>`, im Browser `https://localhost:8443` öffnen. | Zertifikatswarnung (erwartet, temporäres Zertifikat), danach der Einrichtungsassistent. | ☐ |
| 2.3 | Token eingeben. | Weiter zum Schritt Domain. | ☐ |
| 2.4 | Domain `<DOMAIN>`, Port 8443. | Prüfung von DNS und Port grün. | ☐ |
| 2.5 | Netzfreigabe: vorgeschlagene IP übernehmen (`<DEINE-IP>/32`). | Weiter zum Zertifikat. | ☐ |
| 2.6 | Zertifikat: **Let’s Encrypt über HTTP-01**, Zertifizierungsstelle **Let’s Encrypt (vertrauenswürdig)**, Nutzungsbedingungen akzeptieren, anfordern. Währenddessen auf der VM `ufw status` aufrufen. | Live-Fortschritt; `ufw status` zeigt kurz eine Regel für Port 80 mit Kommentar `daemonica:acme:window`, danach ist sie wieder weg. Zertifikat installiert. | ☐ |
| 2.7 | Weiter zum Umschalten. | Hinweis auf `https://<DOMAIN>:8443`. Der SSH-Tunnel wird nicht mehr gebraucht. | ☐ |
| 2.8 | `https://<DOMAIN>:8443` öffnen. | Gültiges Zertifikat (Schloss ohne Warnung), Assistent beim Schritt Passkey. | ☐ |
| 2.9 | Konto `pancake`, Linux-Benutzer `pancake`, Passkey-Name vergeben, Passkey registrieren. | Angemeldet, Übersicht erscheint, Hinweis auf einen zweiten Passkey. | ☐ |
| 2.10 | Den alten Token aus 2.1 noch einmal verwenden (`https://<DOMAIN>:8443/setup`) und `daemonica-admin bootstrap` auf der VM. | Token abgelehnt; `bootstrap` meldet, dass die Einrichtung abgeschlossen ist. | ☐ |

## 3. Anmeldung, Passkeys, Sitzungen

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 3.1 | Abmelden, mit Passkey wieder anmelden. | Anmeldung ohne Benutzername oder Passwort. | ☐ |
| 3.2 | Sicherheit → Passkeys: zweiten Passkey (Handy) hinzufügen, einen umbenennen. | Passkey-Bestätigung wird verlangt; Liste zeigt beide. | ☐ |
| 3.3 | Versuchen, den letzten verbliebenen Passkey zu entfernen (erst einen löschen, dann den anderen). | Der letzte lässt sich nicht entfernen. Danach den zweiten wieder hinzufügen. | ☐ |
| 3.4 | Mit dem Handy anmelden; am Rechner Sicherheit → Sitzungen. | Zwei Sitzungen; die Handy-Sitzung lässt sich beenden, das Handy ist danach abgemeldet. | ☐ |
| 3.5 | Eine geschützte Aktion ausführen (z. B. 3.2), innerhalb von 5 Minuten eine zweite. | Erste fragt nach dem Passkey, zweite nicht. | ☐ |

## 4. Module

Die Module ab M1.3 hast du bereits einzeln abgenommen; hier genügt ein kurzer Durchgang.
Bei Übersicht und Benutzern (M1.1, M1.2) steht deine Abnahme noch aus, daher dort genauer.

| # | Modul | Schritt | Erwartung | ☐ |
|---|---|---|---|---|
| 4.1 | Übersicht | Werte mit `top`, `free -m` und `df -h` auf der VM vergleichen. | CPU, RAM, Swap, Datenträger und Laufzeit passen. „Letzte Anmeldungen“ zeigt deine SSH-Anmeldung. | ☐ |
| 4.2 | Dienste | `cron` neu starten, Journal des Dienstes öffnen. | Neustart mit Passkey-Bestätigung, Journal zeigt den Neustart. | ☐ |
| 4.3 | Logs | journald live verfolgen; Quelle „Datei“ → `auth.log`. | Neue Zeilen erscheinen; `auth.log` zeigt deine SSH-Anmeldung; Export als Text. | ☐ |
| 4.4 | Prozesse | Auf der VM `sleep 600 &`, im Dashboard suchen und beenden. | Prozess verschwindet; die Liste passt zu `top`. | ☐ |
| 4.5 | Benutzer | Testbenutzer `abnahme` anlegen, Gruppe zuordnen, wieder löschen. Spalte „Letzte Anmeldung“ ansehen. | Änderungen sichtbar, `id abnahme` passt; `pancake` zeigt die letzte Anmeldung. | ☐ |
| 4.6 | SSH-Schlüssel | Für `op` einen öffentlichen Schlüssel eintragen; einen kaputten Schlüssel versuchen. | Gültiger Schlüssel gespeichert, kaputter abgelehnt; sshd-Einstellungen nur lesend. | ☐ |
| 4.7 | Dateien | In `/home/pancake` eine Datei anlegen, bearbeiten, herunterladen, eine hochladen; eine Datei in `/etc` bearbeiten. | Funktioniert; bei `/etc` Prüfung und Vorversion. | ☐ |
| 4.8 | Terminal | Terminal öffnen, `id` eingeben; erhöhten Modus starten. | Läuft als `pancake`; erhöhter Modus verlangt den Passkey und läuft als root. | ☐ |
| 4.9 | Netzwerk | Ansicht prüfen (keine Änderung ohne Snapshot). | Schnittstellen, Adressen und Routen stimmen mit `ip a` überein. | ☐ |
| 4.10 | Firewall | Status, Regelwerk und Erklärungen ansehen; Regel „Port 8080 erlauben“ planen, anwenden, bestätigen und wieder löschen. | Ampel stimmt; Regel erscheint in `ufw status` und ist danach wieder weg. | ☐ |
| 4.11 | Firewall-Logs | Von außen einen gesperrten Port ansprechen (z. B. `nc -vz <VM-IP> 5432`). | Eintrag „blockiert“ mit deiner IP erscheint. | ☐ |
| 4.12 | Paketmitschnitt | 1 Minute auf der Hauptschnittstelle mitschneiden, Live-Ansicht ansehen, Datei herunterladen. | Pakete sichtbar, Dashboard-Port ausgenommen, `.pcap` lässt sich herunterladen. | ☐ |
| 4.13 | Jobs | Job „date ausgeben“ täglich anlegen, „Jetzt ausführen“, Ausgabe ansehen, löschen. | Ausgabe mit Datum; Job weg. | ☐ |
| 4.14 | Updates | Updates prüfen und simulieren; optional `cowsay` installieren und wieder entfernen. | Simulation zeigt die Pakete; Installation und Entfernung laufen als Job mit Protokoll. | ☐ |
| 4.15 | Datenträger | Ansicht prüfen (keine fstab-Änderung ohne Snapshot). | Passt zu `lsblk` und `df -h`. | ☐ |
| 4.16 | Zeit & Host | Zeitzone ändern und zurückstellen. | `timedatectl` zeigt die Änderung. | ☐ |
| 4.17 | Einstellungen → Zertifikat | Ansicht prüfen. | Let’s Encrypt, gültig bis, Verfahren HTTP-01, Erneuerung automatisch. | ☐ |

### 4a. Zertifikat wechseln mit DNS-01 (geführt) und Rückweg über die Konsole

Dieser Teil prüft den geführten DNS-01-Ablauf gegen Let’s Encrypt **Staging** und den
Rückweg, wenn der Browser einem Zertifikat nicht mehr vertraut.

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 4a.1 | Einstellungen → Zertifikat wechseln → „Let’s Encrypt über DNS-01 (geführt)“, Zertifizierungsstelle **Staging**. | Deutliche Warnung, dass Passkeys mit einem Staging-Zertifikat nicht mehr funktionieren. | ☐ |
| 4a.2 | Anfordern. | Anzeige von Typ TXT, Name (`_acme-challenge.daemonica.404squad.cloud`) und Wert mit Kopier-Knöpfen. | ☐ |
| 4a.3 | Bei Hostinger im DNS-Editor den TXT-Eintrag anlegen (Name meist nur `_acme-challenge.daemonica`), dann „Eintrag ist gesetzt, jetzt prüfen“. | Prüfversuche werden angezeigt; nach einigen Minuten ist das Staging-Zertifikat installiert. | ☐ |
| 4a.4 | Seite neu laden. | Browser warnt vor dem Zertifikat (erwartet). | ☐ |
| 4a.5 | Auf der VM: `daemonica-admin tls-issue --agree-tos` | Ausstellung über HTTP-01 bei Let’s Encrypt; Ausgabe zeigt das neue Zertifikat. | ☐ |
| 4a.6 | Seite neu laden. | Wieder gültiges Zertifikat, Passkey-Anmeldung funktioniert. TXT-Eintrag bei Hostinger löschen. | ☐ |

Hinweis: Let’s Encrypt erlaubt fünf gleiche Zertifikate pro Woche; diese Checkliste braucht zwei.

## 5. Rollen

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 5.1 | Sicherheit → Konten: `op` als **Operator** (Linux-Benutzer `op`) und `leser` als **Nur-Lesen** (Linux-Benutzer `leser`) einladen. | Einladungslink wird einmal angezeigt (60 Minuten gültig). | ☐ |
| 5.2 | Operator-Link im zweiten Browser-Profil öffnen, Passkey registrieren. | Angemeldet als Operator. Navigation ohne Konten, Audit-Log und Einstellungen. | ☐ |
| 5.3 | Als Operator: Terminal öffnen (`id` → `op`), Prozesse eines anderen Benutzers beenden versuchen. | Terminal läuft als `op`; fremde Prozesse lassen sich nicht beenden. | ☐ |
| 5.4 | Nur-Lesen-Link im privaten Fenster öffnen, Passkey registrieren. | Navigation ohne Terminal, Dateien, Logs und ohne Verwaltungsbereiche; keine Änderungsknöpfe. | ☐ |
| 5.5 | Als Admin das Konto `leser` deaktivieren. | Die Sitzung von `leser` endet beim nächsten Klick. | ☐ |

## 6. Sicherheit und Notfall

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 6.1 | Handy ohne WLAN (andere IP) auf `https://<DOMAIN>:8443`. | Keine Verbindung (nicht freigegebene IP). | ☐ |
| 6.2 | Einstellungen → Netzfreigabe: deine IP entfernen, Warnung bestätigen, anwenden und **nicht** bestätigen. | Verbindung bricht ab; nach 90 Sekunden ist die alte Freigabe automatisch zurück und du kommst wieder hinein. | ☐ |
| 6.3 | `daemonica-admin recover pancake` auf der VM, dann auf der Anmeldeseite „Ich habe ein Wiederherstellungs-Token“. | Neuer Passkey registriert; die bisherigen Sitzungen von `pancake` sind beendet. | ☐ |
| 6.4 | Sicherheit → Audit-Log ansehen; auf der VM `daemonica-admin audit-verify` und `lsattr /var/log/daemonica/audit.log`. | Alle Aktionen dieser Abnahme stehen im Log; Kette intakt; Attribut `a` (nur anhängen) gesetzt. | ☐ |
| 6.5 | `daemonica-admin tls-status` | Domain, Aussteller, Restlaufzeit. | ☐ |

## 7. Update und Rollback

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 7.1 | Dasselbe Paket noch einmal installieren: `apt install --reinstall ./daemonica_0.1.0~rc1_amd64-UNSIGNED-TESTONLY.deb` | Dienste starten neu, Konten, Passkeys und Audit-Log bleiben; nach erneuter Anmeldung ist alles wie vorher. | ☐ |
| 7.2 | `ls /var/lib/daemonica-helper/backups/` | Ordner vorhanden. Eine Sicherung der Kontendatenbank entsteht nur bei Updates, die die Datenbank ändern; bei derselben Version bleibt er leer. Den Weg von einer älteren Version auf diesen Stand und zurück prüfe ich im Gesamttest; die Schritte stehen in `docs/INSTALL.md` §5. | ☐ |

## 8. Deinstallation

| # | Schritt | Erwartung | ☐ |
|---|---|---|---|
| 8.1 | `apt remove daemonica` | Dienste weg, `/var/lib/daemonica*` und `/var/log/daemonica` noch da; `ufw status` ohne `daemonica:acme:window`. | ☐ |
| 8.2 | Paket wieder installieren (1.2). | Dashboard sofort wieder auf `<DOMAIN>` erreichbar, Anmeldung mit dem bisherigen Passkey. | ☐ |
| 8.3 | `apt purge daemonica` | `/var/lib/daemonica`, `/var/lib/daemonica-helper`, `/var/log/daemonica` gelöscht; keine `daemonica-job-*`-Units mehr (`systemctl list-units 'daemonica-*'`). | ☐ |
| 8.4 | `ufw status numbered` | Regeln mit Kommentar `daemonica:` bleiben bewusst stehen (Zugang reißt nicht ab); bei Bedarf von Hand löschen. | ☐ |

## 9. Ergebnis

- ☐ Alle Schritte ohne Abweichung → bitte „**Phase 1 abgenommen**“ schreiben.
- ☐ Abweichungen (Schritt-Nummer und was passiert ist):

---

## Bekannte Einschränkungen

Diese Punkte sind bewusst nicht oder nur teilweise in Phase 1 enthalten.

**KANN-Anforderungen, nicht umgesetzt**
- Ordner als Archiv herunterladen (Dateimanager).
- Terminal: Hintergrundprozesse über das Schließen hinaus behalten, automatisches Wiederverbinden nach kurzen Abbrüchen.
- `at`-Jobs; Cron-Einträge per Knopf in systemd-Timer umwandeln.
- apt-Sperren (Holds).
- LVM, RAID und SMART auf der Datenträger-Seite.
- DNS-Anbieter-Plugins für DNS-01 (der geführte, manuelle Ablauf ist enthalten).
- `lynis` und OWASP-ZAP im Audit (lynis läuft im Gesamttest auf der VM, ZAP nicht).

**SOLL-Anforderung mit Abweichung (bereits in M1.5 abgenommen)**
- Netzwerk: Schreiben nur für netplan und ifupdown; NetworkManager und systemd-networkd werden nur angezeigt (DEC-024).

**Weitere Grenzen**
- DNS-01-Zertifikate werden nicht automatisch erneuert (jeder neue TXT-Wert braucht dich); Daemonica warnt 30 Tage vorher, die Erneuerung geht in den Einstellungen oder mit `daemonica-admin tls-issue --method dns-01`.
- Firewall-Verwaltung nur über ufw; andere Backends nur lesend (A-12). sshd-Konfiguration nur lesend (A-11).
- Vom Kernel unterdrückte Firewall-Logzeilen werden gezählt und angezeigt; was ufw selbst per Ratenbegrenzung verwirft, ist nicht erkennbar.
- Keine Obergrenze für gleichzeitige Sitzungen eines Kontos (Audit F-07, begrenzt durch die Anmelde-Ratenbegrenzung); Anmeldeversuche aus einem freigegebenen Netz können die Anmeldung für alle kurz verlangsamen (Audit F-08). Beides ist für Phase 2 vorgemerkt.
- Das Paket ist nicht signiert (`-UNSIGNED-TESTONLY`), reproduzierbare Builds sind nicht geprüft. arm64 wird gebaut, aber nicht auf echter Hardware getestet.
- Audit-Log: höchstens fünf Dateien à 32 MiB; ältere Einträge stehen nur noch im Journal.

## Annahmen zur Bestätigung

Die SPEC führt Annahmen, die ich ohne ausdrückliche Bestätigung getroffen habe. Bitte je
Zeile „ja“ oder deine Korrektur. A-01 und A-25 bis A-29 hast du bereits bestätigt.

| ID | Annahme | Stand in Phase 1 | Bestätigt? |
|---|---|---|---|
| A-02 | Architekturen amd64 und arm64. | Beide werden gebaut; getestet nur amd64. | ☐ |
| A-03 | Standardport 8443; Ersteinrichtung nur über Loopback/SSH-Tunnel bzw. das beim Bootstrap angegebene Netz. | So umgesetzt. | ☐ |
| A-04 | SQLite (`modernc.org/sqlite`, ohne CGO); getrennte Datenbanken für Helper und Web, `metrics.db` in Phase 2. | Helper-Datenbank umgesetzt; der Web-Prozess speichert keine Sitzungsdaten. | ☐ |
| A-05 | UI: Tailwind + Radix, Inter/JetBrains Mono selbst gehostet, CodeMirror 6, xterm.js, uPlot. | So umgesetzt (uPlot ab Phase 2 für Metriken). | ☐ |
| A-06 | Sitzungen: Leerlauf 30 min, absolut 12 h, Step-up 5 min, nur in Grenzen einstellbar. | So umgesetzt (5–60 min / 1–24 h). | ☐ |
| A-07 | Zwei Passkeys dringend empfohlen, nicht erzwungen; der letzte ist nicht löschbar. | So umgesetzt. | ☐ |
| A-08 | Erhöhter Terminalmodus nur für Admin, höchstens 30 min; normale Shell mit `no_new_privs`. | So umgesetzt. | ☐ |
| A-09 | Rollenmatrix nach Anhang A (Nur-Lesen ohne Logs, Dateien, Terminal). | So umgesetzt, im E2E-Test geprüft. | ☐ |
| A-10 | Terminal-Eingaben werden nicht aufgezeichnet; Audit-Log führt der Helper (Hash-Kette). | So umgesetzt. | ☐ |
| A-11 | sshd-Konfiguration in Phase 1 nur lesbar. | So umgesetzt. | ☐ |
| A-12 | Firewall-Verwaltung über ufw; andere Backends nur lesend. | So umgesetzt. | ☐ |
| A-13 | Verwaltete Jobs als systemd-Timer; Cron wird angezeigt und (SOLL) bearbeitet. | Beides umgesetzt. | ☐ |
| A-14 | ACME: DNS-01 geführt/manuell (Plugins KANN), HTTP-01/TLS-ALPN-01 nur bei freien Ports; Tests gegen Staging. | So umgesetzt. | ☐ |
| A-15 | Docker: offizielles Docker-Repository als Standard, Distributionspakete als Option. | Phase 3. | ☐ |
| A-16 | Matrix: Synapse; Föderation und Registrierung standardmäßig aus. | Phase 3. | ☐ |
| A-17 | Nextcloud: Apache-Image + PostgreSQL + Redis, ohne Collabora/Talk. | Phase 3. | ☐ |
| A-18 | FreeRADIUS: lokale SQLite-Benutzer, PEAP-MSCHAPv2/EAP-TTLS, EAP-TLS (SOLL), LDAP/AD KANN. | Phase 3. | ☐ |
| A-19 | App-Katalog signiert im Paket, Images per Digest; Updates über Daemonica-Releases. | Phase 3. | ☐ |
| A-20 | Keine Lizenz festgelegt (`LICENSE` ist ein Platzhalter). | Unverändert; bitte Lizenz festlegen oder bestätigen. | ☐ |
| A-21 | Kein Self-Update; Updates nur über apt. | So umgesetzt. | ☐ |
| A-22 | Metriken: 48 h roh / 30 d (1 min) / 400 d (15 min), Limit 1 GiB. | Phase 2. | ☐ |
| A-23 | Checklisten-Referenzen (CIS/BSI) nur als Verweis, eigene Formulierungen. | Phase 2. | ☐ |
| A-24 | Repository-Hosting und CI nicht vorgegeben: lokale `make`-Ziele, Commits auf Englisch. | GitHub-Repository `PanPakaPancake/Daemonica` statt nur lokal, Prüfungen über `make`, kein CI. Einige M1.8-Commit-Texte sind versehentlich auf Deutsch; ab jetzt wieder Englisch. | ☐ |

## Entscheidungen, die du treffen musst

Aus dem Sicherheitsaudit ist keine offen: alle mittleren Befunde sind behoben
(`docs/security/AUDIT-PHASE-1.md`). Offen ist nur die Lizenzfrage aus A-20.
