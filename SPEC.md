# Daemonica — Projektspezifikation (SPEC.md)

> **Version 1.3 · Stand 2026-10-24 · Ausführung durch ein KI-Modell · Abnahme durch den Auftraggeber**
>
> Sprache dieses Dokuments: Deutsch.
> Quellcode, Kommentare, Bezeichner, Commit-Messages, API-Doku und technische Doku (`docs/ARCHITECTURE.md` usw.): **Englisch**.
> Installations- und Abnahmedokumente für den Auftraggeber (`docs/INSTALL.md`, `docs/acceptance/*`): **Deutsch**.
> Benutzeroberfläche: **Deutsch (Standard) und Englisch** über i18n.

---

## 0. Lesehinweise für das ausführende KI-Modell

### 0.1 Verbindlichkeit

| Wort | Bedeutung |
|---|---|
| **MUSS** / **DARF NICHT** | Zwingend. Abweichung nur nach Freigabe des Auftraggebers (siehe 0.3, S3). |
| **SOLL** | Standardmäßig umsetzen. Abweichung nur mit Begründung in `docs/DECISIONS.md`. |
| **KANN** | Optional. Nur umsetzen, wenn Aufwand und Risiko gering sind; sonst Backlog. |

### 0.2 Rangfolge bei Widersprüchen

1. Sicherheitsanforderungen (§3)
2. Verbindliche Entscheidungen (§2)
3. Phasen-Anforderungen (§7–§9)
4. Nutzbarkeit
5. Design
6. Komfort

Der höhere Rang gewinnt. Jeder erkannte Widerspruch wird in `docs/DECISIONS.md` protokolliert, zusammen mit der gewählten Auflösung.

### 0.3 Rückfragen-Policy (wichtig)

Dieses Dokument ist so geschrieben, dass du **ohne Rückfragen** arbeiten kannst. Triff bei Lücken die **sicherste und konservativste** sinnvolle Annahme, setze sie um und protokolliere sie in `docs/DECISIONS.md` (ID, Datum, Kontext, Entscheidung, verworfene Alternativen, Sicherheitsbewertung).

Du **MUSST anhalten und den Auftraggeber fragen**, ausschließlich in diesen Fällen:

| ID | Stopp-Bedingung |
|---|---|
| S1 | **Phasen-Gate:** Ein Abnahmepaket (§6.6) ist fertig. Danach warten, bis der Auftraggeber ausdrücklich „Phase N abgenommen“ schreibt. |
| S2 | **Fehlende Geheimnisse oder Zugänge:** Zugang zur Test-VM, Domain, DNS-API-Token, Signierschlüssel für Pakete. Nie selbst erfinden oder Produktivschlüssel erzeugen. |
| S3 | **Sicherheitsabschwächung:** Eine Anforderung ist nur erfüllbar, indem eine Vorgabe aus §2 oder §3 abgeschwächt wird. |
| S4 | **Außerhalb der Test-VM:** Eine Aktion würde andere Systeme berühren oder ist irreversibel/destruktiv für fremde Daten. |
| S5 | **Unerfüllbares MUSS:** Eine MUSS-Anforderung ist technisch nicht erfüllbar. Belege liefern und Alternativen vorschlagen. |

Alles andere entscheidest du selbst.

### 0.4 Arbeitsschleife (pro Meilenstein)

1. **Plan:** Kurze Design-Notiz bzw. ADR in `docs/DECISIONS.md`.
2. **Umsetzung:** Backend, Frontend, Paketierung, Doku.
3. **Tests:** Unit, Integration auf der Test-VM, E2E, Negativ- und Sicherheitstests (§6.4).
4. **Selbst-Review** gegen die Mini-Sicherheitscheckliste (§6.5, Spalte „laufend“).
5. **Doku und `docs/STATUS.md`** aktualisieren.
6. **Commit** (kleine, atomare Commits, Conventional Commits, Englisch).

Ein Meilenstein gilt erst als fertig, wenn `make lint test sec` grün ist und die Definition of Done (§6.3) erfüllt ist.

### 0.5 Pflichtdokumente im Repository

`README.md`, `CHANGELOG.md`, `SECURITY.md`, `docs/STATUS.md` (Fortschritt gegen diese Spec), `docs/DECISIONS.md`, `docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`, `docs/INSTALL.md` (de), `docs/security/AUDIT-PHASE-<N>.md`, `docs/acceptance/ACCEPTANCE-PHASE-<N>.md`.

---

## 1. Projektziel, Umfang, Nicht-Ziele

**Daemonica** ist ein webbasiertes Systemverwaltungsdashboard für Linux-Server. Es liest Systeminformationen aus und erledigt tägliche Administrationsaufgaben. Es läuft **direkt auf dem verwalteten Server**; eine Instanz verwaltet genau diesen einen Host.

**Leitprinzipien**

1. **Sicherheit zuerst:** Schutz der Daten und Minimierung der Angriffsfläche haben in jeder Phase Vorrang vor Funktionsumfang und Komfort.
2. **Geführte Bedienung:** Die Oberfläche leitet bei notwendigen Konfigurationsschritten durch Assistenten, erklärt Auswirkungen in verständlicher Sprache und setzt keine Linux-Vorkenntnisse für Standardaufgaben voraus.
3. **Nutzbarkeit vor Design:** Das Design folgt der Markenwelt (§5), darf aber nie die Bedienbarkeit beeinträchtigen.
4. **Nachvollziehbarkeit:** Alles Relevante wird auditiert, alles Riskante vorab als Plan gezeigt und, wo möglich, rückgängig machbar gemacht.

**Nicht-Ziele (DARF NICHT umgesetzt werden)**

- Verwaltung mehrerer Server oder Flotten-/Agent-Betrieb.
- Andere Distributionen als Debian/Ubuntu; Systeme ohne systemd.
- Anmeldung per Passwort, TOTP, SMS, E-Mail-Link, SSO/OIDC/LDAP (Login ausschließlich per Passkey).
- Partitionieren und Formatieren von Datenträgern.
- Kubernetes, Cloud-Provider-Integration, Multi-Tenancy.
- Selbst-Update der Daemonica-Binaries (Updates ausschließlich über apt/.deb).
- Telemetrie oder Verbindungen zu Drittdiensten, die nicht ausdrücklich konfiguriert sind.
- Vollständige Protokoll-Dissektion oder TLS-Entschlüsselung von Paketmitschnitten (kein Wireshark-Ersatz; Mitschnitte werden zur externen Analyse als `.pcap` bereitgestellt).

---

## 2. Verbindliche Entscheidungen des Auftraggebers

| ID | Entscheidung |
|---|---|
| D-01 | **Stack:** Frontend React + TypeScript (strict); Backend Go. |
| D-02 | Läuft direkt auf dem überwachten Server; eine Instanz verwaltet nur diesen Host. |
| D-03 | **Zielsysteme:** Debian-Familie (Debian + Ubuntu), systemd-basiert. Konkrete Versionsmatrix siehe §6.1. |
| D-04 | **Rechtemodell zweigeteilt:** unprivilegierter Web-Dienst + kleiner privilegierter Helfer (§3.2). |
| D-05 | **Erreichbarkeit:** HTTPS direkt im Go-Programm, eigene Domain, Let’s Encrypt (zusätzlich eigene Zertifikate). **Standard: nur freigegebene IP-Netze/VPN**; öffentlich nur durch bewusste Umstellung. Die Sicherheit ist bei jeder Detailentscheidung abzuwägen; im Zweifel die restriktivere Variante. |
| D-06 | **Login ausschließlich mit Passkey (WebAuthn)**, User Verification erforderlich. Kein Passwort, kein anderer Faktor, kein Fallback. |
| D-07 | **Wiederherstellung** bei Verlust aller Passkeys ausschließlich per Konsolenbefehl als root auf dem Server. |
| D-08 | **Konten:** eigene Dashboard-Konten mit Rollen **Admin, Operator, Nur-Lesen**; jedes Konto ist einem Linux-Benutzer zugeordnet. |
| D-09 | **Web-CLI:** echte Shell (PTY). Root/sudo nur nach erneuter Passkey-Bestätigung (Step-up). |
| D-10 | **UI-Sprachen:** Deutsch (Standard) und Englisch. |
| D-11 | **Sicherheitsaudit nach jeder Phase:** automatische Prüfwerkzeuge plus KI-Review nach festem Katalog (§6.5), Bericht als Datei. |
| D-12 | **Phase-1-Umfang:** SSH-Schlüssel, Benutzer, Netzwerk, Aufgaben/Jobs, Dienststatus, Web-CLI, Dateimanager mit Editor und Up-/Download sowie Systemübersicht, Paket-/Sicherheitsupdates (apt), Firewall (**Status, Regelwerk, Firewall-Logs, Paketmitschnitt**; nftables/ufw), Logs (journald), Prozesse, Datenträger/Mounts, Systemzeit/Hostname/Neustart/Herunterfahren. |
| D-13 | **Verteilung:** `.deb`-Paket mit systemd-Units; signiertes apt-Repository oder signiertes Release-Artefakt. |
| D-14 | **Entwicklung/Test:** Du erhältst eine Debian-/Ubuntu-Test-VM mit root-Zugriff und führst Befehle direkt aus (Regeln §6.1). |
| D-15 | **Phasen-Gates:** Nach jeder Phase Sicherheitsaudit, dann Abnahmepaket, dann Stopp bis zur Freigabe (S1). |
| D-16 | **Phase 2:** Checkliste behebt Abweichungen **per Klick mit Vorschau und Bestätigung** (keine stille Selbstheilung). Alarmierung per Webhook, Mail und API. Regelwerk statisch **und** dynamisch (Baseline-Abweichung, Trendvorhersage). |
| D-17 | **Phase 3:** Docker. Empfohlene Vorauswahl: Nextcloud und Matrix **in Docker**, nginx und FreeRADIUS **nativ** auf dem Server. **Zusatz:** Die Betriebsart (nativ oder Docker) ist für **jede** Anwendung im Wizard wählbar. Beim Einrichten der Anwendungen können notwendige **Firewallfreigaben optional automatisch** angelegt werden. |
| D-18 | **Design:** Designsprache und Farbpalette aus den mitgelieferten Bildern ableiten (§5); Logo und Maskottchen dürfen unverändert übernommen werden. |
| D-19 | **Nur offizielle Quellen:** Alle Paketquellen (Repositories), Archive und Container-Images stammen ausschließlich aus den **offiziellen Quellen** des jeweiligen Herstellers/Projekts bzw. der Distribution. Verboten sind PPAs, inoffizielle Mirrors, Community-Builds, Images ungeprüfter Publisher und aus dem Netz nachgeladene Installer-Skripte (Pipe-to-Shell). |

---

## 3. Sicherheitsarchitektur (verbindlich für alle Phasen)

### 3.1 Schutzziele und Bedrohungsmodell

Schutzziele: Vertraulichkeit der Serverdaten, Integrität der Konfiguration, Verfügbarkeit des Hosts und des Dashboards.

| Angreifer | Beschreibung |
|---|---|
| A1 | Unauthentifizierter Netzwerkangreifer |
| A2 | Angreifer mit gestohlener Sitzung oder Phishing-Versuch gegen einen Benutzer |
| A3 | Angreifer mit Codeausführung **im Web-Prozess** (z. B. durch Schwachstelle) |
| A4 | Kompromittierte Abhängigkeit (Supply Chain) |
| A5 | Authentifizierter Benutzer mit niedriger Rolle (Rechteausweitung) |
| A6 | Lokaler unprivilegierter Linux-Benutzer |

**Designziel:** Selbst bei Kompromittierung des Web-Prozesses (A3) darf der Angreifer **keine beliebige Code-Ausführung als root** erlangen, sondern höchstens typisierte, autorisierte Operationen im Rahmen der aktuell angemeldeten Benutzer auslösen. Das Bedrohungsmodell wird in `docs/THREAT-MODEL.md` (STRIDE-orientiert) geführt und je Phase aktualisiert.

**Minimale Angriffsfläche vor dem Login:** Es sind **nur** erreichbar: Login-Seite samt statischen Assets, die WebAuthn-Login-Endpunkte und (nur im Setup-/Enroll-Modus) die Enrollment-Endpunkte. Keine Debug-Endpunkte, kein `pprof`, keine Versionsbanner, keine Default-Zugangsdaten.

### 3.2 Prozess- und Rechtemodell

| Komponente | Benutzer | Aufgabe |
|---|---|---|
| `daemonica-web` | `daemonica-web` (kein Login, keine Shell) | HTTPS, API, WebSocket, eingebettete UI, Sitzungen, Metriken (Phase 2). Keine Capabilities (außer ggf. `CAP_NET_BIND_SERVICE`). |
| `daemonica-helper` | root | Führt privilegierte Operationen aus. Lauscht **nur** auf Unix-Sockets, nie auf TCP. |
| `daemonica-admin` | root (CLI) | Bootstrap, Recovery, Notfall-Befehle. Spricht über einen zweiten, root-exklusiven Socket (`/run/daemonica/admin.sock`, `0600`) mit dem Helper. |

**MUSS-Regeln**

1. **Web↔Helper-Kommunikation** nur über `/run/daemonica/helper.sock` (`0660 root:daemonica-web`). Der Helper prüft `SO_PEERCRED` (nur UID `daemonica-web`). Protokoll versioniert, längenpräfigiert, max. Nachrichtengröße 1 MiB, große Daten über Streams.
2. **Typisierte Operationen:** Der Helper kennt ausschließlich eine feste Allowlist benannter Operationen mit Schema-Validierung (Anhang D). Es gibt **keine** generische „führe Befehl aus“-Operation. Einzige Freitext-Ausführung ist `pty.open` (§7, M1.4).
3. **Vertrauensanker ist der Helper:** Konten, Rollen, Linux-Zuordnung, Passkey-Public-Keys, Grants und Step-up-Zustand liegen in einer **helper-eigenen** Datenbank (`/var/lib/daemonica-helper/accounts.db`, `root:root 0600`). Der Web-Prozess hat eine eigene Datenbank (`/var/lib/daemonica/web.db`, `daemonica-web 0600`) für Sitzungsmetadaten, UI-Einstellungen, Metriken u. Ä.
4. **Der Helper autorisiert jede Operation selbst** anhand eines von ihm ausgestellten Grants (Konto → Rolle → Linux-Benutzer → Step-up-Status). Er vertraut **niemals** Rollen- oder Benutzerangaben des Web-Prozesses.
5. **Passkey-Verifikation im Helper:** Die WebAuthn-Zeremonien (Login und Step-up) werden vom Helper verifiziert; der Web-Prozess reicht Nachrichten nur durch. Ein kompromittierter Web-Prozess kann keine Step-ups fälschen.
6. **Worker-Prozesse:** Dateizugriffe und Terminals laufen in einem Kindprozess, der **vor jedem Dateizugriff** die Credentials des zugeordneten Linux-Benutzers annimmt (`setgroups/initgroups`, `setresgid`, `setresuid`, `no_new_privs`, Capabilities ablegen). Nur im „erhöhten Modus“ nach Step-up bleibt der Worker root.
7. **Externe Programme** (`useradd`, `apt-get`, `ufw` …) nur mit `exec` + argv-Array, absolute Pfade, bereinigte Umgebung (`PATH` fest, `LANG=C.UTF-8`), Timeout, Ausgabelimit, Kontext-Abbruch. **Nie** `sh -c` mit Benutzereingaben. Eingaben per Allowlist-Regex/Parser validieren (z. B. Benutzername `^[a-z_][a-z0-9_-]{0,31}$`).
8. **Konfigurationsänderungen** sind atomar (temp + `fsync` + `rename`), sperren konkurrierende Änderungen, legen vorher ein Backup an (`/var/lib/daemonica-helper/backups/<zeit>/`), validieren vor Aktivierung und sind rückgängig machbar.
9. **Selbstaussperr-Schutz:** Der Helper verweigert ohne Step-up und ausdrückliche Zusatzbestätigung Aktionen, die den Zugang zerstören würden. Dazu zählen: Löschen/Sperren des Linux-Benutzers eines aktiven Admins, Stoppen oder Deaktivieren von `daemonica-*`-Units, Firewall-Regeln, die Dashboard- oder SSH-Port aussperren, Netzwerk- oder Allowlist-Änderungen ohne Bestätigungs-Timer.
10. **Plan → Apply → Confirm:** Riskante Änderungen (Netzwerk, Firewall, Allowlist, SSH, fstab, später PAM/sudo) laufen als Plan (Diff/Vorschau) → Apply → **Bestätigungs-Timer** (Standard 90 s). Bleibt die Bestätigung aus, wird automatisch zurückgerollt. Der Rollback-Timer muss **unabhängig vom Browser und vom Web-Prozess** laufen (Helper-Timer bzw. transienter systemd-Timer), damit er auch bei Verbindungsverlust greift.

### 3.3 Authentifizierung (nur Passkey)

- **WebAuthn Level 2** (empfohlen: `github.com/go-webauthn/webauthn`). `userVerification: required`, `residentKey: required` (Discoverable Credentials, Login **ohne Benutzernamen**), `attestation: none`.
- RP-ID = konfigurierte Domain, Origin exakt geprüft. Challenges: 32 Byte zufällig, einmalig, TTL 120 s. Signaturzähler/Klon-Erkennung prüfen, sofern der Authenticator zählt. Flags *backup-eligible/backed-up* speichern und in der UI anzeigen („synchronisierter Passkey“ vs. „gerätegebunden“).
- **Kein Passwort, kein „Passwort vergessen“, keine E-Mail-Wiederherstellung.** Fehlermeldungen beim Login sind einheitlich (keine Konto-Enumeration).
- **Login-Härtung:** Rate-Limits pro IP und global, Backoff pro IP (kein Konto-Lockout, um DoS zu vermeiden), alles auditiert.
- **Passkeys verwalten:** Hinzufügen nur in angemeldeter Sitzung + Step-up. Das Entfernen des letzten Passkeys eines Kontos ist verboten. Solange ein Konto weniger als **zwei** Passkeys besitzt, zeigt die UI einen dauerhaften Hinweis „Zweiten Passkey registrieren“.

**Bootstrap (Ersteinrichtung)**

1. Die Installation startet keinen öffentlichen Listener. Der Dienst bindet zunächst nur an `127.0.0.1:8443` und ist im **Setup-Modus**.
2. `sudo daemonica-admin bootstrap [--allow <CIDR>]` erzeugt ein **Einmal-Token** (256 Bit, 60 min gültig, einmalig, nur gehasht gespeichert) und gibt eine Anleitung aus. Zugriff zunächst per SSH-Tunnel auf Loopback; das Tool schlägt anhand von `SSH_CLIENT` das aktuelle Client-Netz als Allowlist-Eintrag vor.
3. Der **Setup-Assistent** (§7, M1.0) führt durch Domain, Zertifikat (TLS), Netzfreigabe (Allowlist) und die Registrierung des ersten Admin-Passkeys **auf der endgültigen Domain** (Passkeys sind an die RP-ID gebunden). Im Setup-Modus ist sonst nichts erreichbar.
4. Mit der Registrierung des ersten Passkeys wird das Token verbraucht und der Setup-Modus endet unwiderruflich.

**Recovery:** Ausschließlich `sudo daemonica-admin recover <konto> [--revoke-all]`. Erzeugt ein Einmal-Token (256 Bit, 30 min), beendet alle Sitzungen des Kontos, entfernt auf Wunsch alle alten Passkeys, schreibt einen Audit-Eintrag. Es gibt **keinen** anderen Wiederherstellungsweg.

Weitere `daemonica-admin`-Befehle: `status`, `list-accounts`, `allowlist-reset` (Notfall: setzt die Allowlist auf Loopback), `tls-status`, `audit-verify`.

### 3.4 Autorisierung

- **Deny by default.** Berechtigungen stehen als Konstanten in einem zentralen Policy-Modul **im Helper** (die Web-API prüft zusätzlich für die UX). Rollenmatrix: **Anhang A**.
- **Zuordnung Konto → Linux-Benutzer:** Jedes Konto ist genau einem existierenden Linux-Benutzer zugeordnet. Zuordnung zu UID 0 ist **verboten**; Root-Rechte gibt es nur im erhöhten Modus nach Step-up.
- **Step-up:** frische Passkey-Verifikation (UV erforderlich), gültig **5 Minuten**, an Sitzung und Aktionsklasse gebunden. Welche Aktionen Step-up verlangen, regelt Anhang A (Markierung **(S)**).
- **Tests:** Eine Autorisierungs-Testmatrix wird **aus der Policy-Tabelle generiert** (jeder Endpunkt × jede Rolle × Step-up an/aus).

### 3.5 Sitzungen und Web-Sicherheit

- Sitzungscookie `__Host-daemonica_session`: `Secure; HttpOnly; SameSite=Strict; Path=/`, 256 Bit Zufall, serverseitig nur als Hash gespeichert, Rotation bei Login und Step-up.
- Lebensdauer: **Idle 30 min, absolut 12 h** (konfigurierbar nur innerhalb Grenzen: Idle 5–60 min, absolut 1–24 h). Sitzungen sind einsehbar und beendbar (eigene; Admin alle).
- **CSRF:** `SameSite=Strict` **plus** Pflicht-Header `X-Daemonica-CSRF` und `Origin`-Prüfung gegen den Host bei jeder zustandsändernden Anfrage. CORS ist deaktiviert.
- **WebSocket:** Origin-Check, einmaliges Ticket (30 s), Nachrichtenraten-Limit, maximale Nachrichtengröße.
- **Header:** strikte CSP (`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`), `require-trusted-types-for 'script'` (SOLL), HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP `same-origin`, restriktive `Permissions-Policy`, `Cache-Control: no-store` für API-Antworten. Keine Inline-Skripte, kein `eval`, keine Drittanbieter-Ressourcen (Fonts selbst hosten).
- **XSS-Disziplin:** `dangerouslySetInnerHTML` ist per Lint-Regel verboten. Alle Daten vom System (Dateinamen, Logs, Prozessnamen, Terminalausgabe in Logansichten) sind **untrusted** und werden als Text gerendert; Steuer-/Escape-Sequenzen in Logansichten werden neutralisiert.
- **Downloads:** immer `Content-Disposition: attachment` + `nosniff`, nie Inline-Rendering benutzerkontrollierter Inhalte; Download-URLs sind einmalige, sitzungsgebundene Tokens (60 s).
- **Robustheit:** Größen-/Zeitlimits (`ReadHeaderTimeout`, Body-Limits pro Route), Fehlerantworten ohne interne Details (RFC 9457, mit Korrelations-ID).

### 3.6 Transport, TLS und Netzzugriff

- **TLS 1.3 only**, ECDSA-P-256-Zertifikate, HSTS auf dem Dashboard-Host (Standard 1 Jahr, ohne Preload). Kein Klartext-HTTP-Listener, außer zeitlich begrenzt für eine ACME-Challenge.
- **Netz-Allowlist (Standard: nur Loopback):** IPv4/IPv6-CIDR-Liste, **in der Anwendung beim Accept** erzwungen (vor dem TLS-Handshake; nicht erlaubte Verbindungen werden sofort geschlossen). Zusätzlich SOLL der Helper eine passende Firewall-Regel erzeugen (Defense in Depth). Änderungen laufen über Plan → Apply → Confirm (§3.2 Nr. 10) und müssen die IP der aktuellen Sitzung enthalten, sonst Warnung mit Typ-zur-Bestätigung.
- **Die Remote-IP ist die TCP-Peer-Adresse.** `X-Forwarded-For` wird nie vertraut; ein `trusted_proxies`-Mechanismus ist nur explizit konfigurierbar.
- **Zertifikatsquellen** (Setup-Assistent und Einstellungen):
  - (a) eigenes Zertifikat (PEM-Upload bzw. Pfad),
  - (b) Let’s Encrypt per **DNS-01, geführt/manuell** (TXT-Record wird angezeigt und geprüft; Erneuerung erfordert erneute Bestätigung; Provider-Plugins KANN),
  - (c) Let’s Encrypt per **HTTP-01 oder TLS-ALPN-01**, nur wenn Port 80 bzw. 443 frei ist (Preflight-Prüfung). Der Helper öffnet für das „ACME-Fenster“ minimal und zeitlich begrenzt die nötige Freigabe und schließt sie danach wieder; im Fenster werden ausschließlich ACME-Handshakes bzw. Challenge-Pfade beantwortet.
- Die ACME-Komponente ist als **wiederverwendbares Modul** zu bauen (wird in Phase 3 für nginx-Domains genutzt). Alle Tests nutzen die **Let’s-Encrypt-Staging-Umgebung**. Ablaufwarnung in der UI bei < 30 Tagen.
- Standard-Port **8443**. Der Betrieb hinter einem Reverse Proxy ist **nicht** Teil von Phase 1.

### 3.7 Geheimnisse und Daten

- Keine Geheimnisse in Repository, Logs, Crash-Dumps, Prozessargumenten oder Umgebungsvariablen.
- Geheimnisse im Ruhezustand (SMTP-Zugang, Webhook-Secrets, App-Passwörter) verschlüsselt (AES-256-GCM oder XChaCha20-Poly1305); Schlüssel per systemd-Credentials (`LoadCredentialEncrypted`), sonst Schlüsseldatei `0400` beim zuständigen Besitzer. Sitzungs- und API-Tokens nur als SHA-256-Hash.
- Uploads landen in einem Temp-Verzeichnis (`0700`) mit Größenlimit, nie unbegrenzt im RAM.
- Keine Telemetrie; ausgehende Verbindungen nur zu ausdrücklich konfigurierten Zielen (ACME, apt, Docker-Registries, Webhook/SMTP-Ziele).

### 3.8 Audit-Log

- Der **Helper** schreibt das maßgebliche Audit-Log: `/var/log/daemonica/audit.log` (JSON Lines, `root:adm 0640`) mit **SHA-256-Hash-Kette** (`prev_hash`). SOLL: `chattr +a`, soweit das Dateisystem es erlaubt. Rotation setzt die Kette fort. Zusätzlich Spiegelung nach journald (`SyslogIdentifier=daemonica-audit`).
- Der Web-Prozess meldet Auth-/Sitzungsereignisse per RPC (`audit.append`) an den Helper.
- **Protokolliert werden:** alle Auth-Ereignisse, Step-ups, alle privilegierten Operationen (auch abgelehnte), Konto-/Rollenänderungen, Terminal-Sitzungen (Start, Ende, Modus, Quell-IP), Paketmitschnitte (Start, Stopp, Interface, Filter, Dauer, Größe, Download, Löschen), schreibende Dateioperationen (Pfad, Größe, Hash bei Upload), Konfigurationsänderungen. Schema: Anhang C.
- **Nie protokolliert:** Passwörter, Tokens, Dateiinhalte, Terminal-Eingaben, Paketinhalte. Sitzungsaufzeichnung ist KANN, standardmäßig AUS und nur für den erhöhten Modus.
- Die UI bietet eine Audit-Ansicht (Admin) mit Filter, Export und **Integritätsprüfung der Kette**.

### 3.9 systemd-Härtung

- `daemonica-web.service` (Zielwert `systemd-analyze security` ≤ 2.0): `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables/Modules/Logs/ControlGroups/Clock/Hostname=yes`, `ProtectProc=invisible`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service ~@privileged ~@resources`, `SystemCallArchitectures=native`, `CapabilityBoundingSet=` (leer bzw. nur `CAP_NET_BIND_SERVICE`), `UMask=0077`, State-/Runtime-/Logs-Directory, `Restart=on-failure`, Watchdog.
- `daemonica-helper.service`: so restriktiv wie funktional möglich (Ziel ≤ 6.0). **Jede nicht gesetzte Härtungsdirektive** wird mit Begründung in `docs/ARCHITECTURE.md` (Tabelle „Hardening exceptions“) dokumentiert. Hinweis: `NoNewPrivileges=yes` ist für den Helper unzulässig, weil sonst `sudo` im erhöhten Terminal nicht funktioniert; Worker im Standardmodus setzen `no_new_privs` selbst.
- Tatsächliche Scores werden im Auditbericht dokumentiert.

---

## 4. Technische Architektur

### 4.1 Technologie-Stack

**Backend (Go)**
- Aktuelle stabile Go-Version zum Projektstart; Toolchain in `go.mod` pinnen. Standardbibliothek zuerst: `net/http` (Method-Patterns), `log/slog`, `context` durchgängig, `CGO_ENABLED=0`.
- Zugelassene Kernabhängigkeiten (jede mit Begründung in `docs/DECISIONS.md`): `go-webauthn/webauthn`, `modernc.org/sqlite` (CGO-frei), `creack/pty`, D-Bus-Anbindung für systemd (`coreos/go-systemd/v22` oder `godbus/dbus/v5`), `golang.org/x/crypto`, ein WebSocket-Paket (`coder/websocket` oder `gorilla/websocket`), `go-acme/lego/v4` (nur benötigte Teile). Jede weitere Abhängigkeit braucht eine ADR.
- Systemzustand wird bevorzugt direkt aus `/proc`, `/sys`, D-Bus und `statfs` gelesen statt durch Parsen von Befehlsausgaben.
- Datenhaltung: SQLite (WAL, `foreign_keys=ON`, `busy_timeout`), einfache vorwärtsgerichtete SQL-Migrationen (eingebettet), vor jeder Migration ein Backup.

**Frontend (React + TypeScript)**
- React (aktuelle stabile Hauptversion), TypeScript mit `strict` und `noUncheckedIndexedAccess`, Vite, React Router, TanStack Query.
- Tailwind CSS + Radix UI Primitives (barrierefreie, headless Komponenten), `react-i18next`, `@xterm/xterm` (Terminal), CodeMirror 6 (Editor), `uPlot` (Zeitreihen, Phase 2).
- Tests: Vitest, Testing Library, Playwright (inkl. `@axe-core/playwright`).
- Das gebaute Frontend wird per `go:embed` in `daemonica-web` eingebettet (ein statisches Binary, keine Node-Laufzeit auf dem Server).

**API**
- REST/JSON unter `/api/v1/*`; WebSocket unter `/api/v1/ws/*` (Terminal, Log-Follow, Live-Metriken).
- **OpenAPI 3.1** (`api/openapi.yaml`) ist der Vertrag. Go-Server-Typen und TS-Client-Typen werden generiert; ein CI-Schritt prüft, dass generierter Code aktuell ist.
- Fehlerformat RFC 9457 (`application/problem+json`) mit stabilem `code` und `correlation_id`. Zeiten ISO 8601 UTC. Cursor-Pagination.
- Lang laufende Aktionen sind „Operations“ mit Fortschritt per WebSocket.
- Riskante Änderungen folgen dem Muster `POST …/plan` → `POST …/apply` → `POST …/confirm` (§3.2 Nr. 10).

### 4.2 Repository-Struktur

```
daemonica/
├─ SPEC.md  README.md  CHANGELOG.md  SECURITY.md  LICENSE (Platzhalter)  Makefile
├─ api/openapi.yaml
├─ cmd/{daemonica-web,daemonica-helper,daemonica-admin}/
├─ internal/
│  ├─ web/        (http, middleware, handlers, ws)
│  ├─ helper/     (rpc-server, ops/*, policy, worker)
│  ├─ rpc/        (geteilte Protokolltypen)
│  ├─ auth/ audit/ store/ acme/ tlsconf/
│  └─ sysinfo/ netcfg/ users/ sshkeys/ jobs/ services/ files/ pty/ apt/ firewall/ disks/ timehost/
│     (Phase 2: checklist/ metrics/ alerts/ notify/   Phase 3: apps/{docker,nginx,freeradius,nextcloud,matrix}/)
├─ web/           (React-App: src/, public/, tests/)
├─ assets/branding/   (daemonica-logo-transparent.png, daemonica-mascot.png + Ableitungen)
├─ packaging/     (nfpm.yaml, systemd/, maintainer-scripts/)
├─ scripts/       (dev-, test-vm-, audit-Skripte, make-apt-repo.sh)
├─ test/          (integration/, e2e/)
└─ docs/          (ARCHITECTURE.md, THREAT-MODEL.md, DECISIONS.md, STATUS.md, INSTALL.md, security/, acceptance/)
```

### 4.3 Build, Paketierung, Release

- **Makefile-Ziele (CI-agnostisch, lokal ausführbar):** `deps`, `lint`, `test`, `test-integration`, `test-e2e`, `sec`, `build`, `package`, `sbom`, `release`.
- **Reproduzierbare Builds:** `-trimpath`, gepinnte Toolchain, `SOURCE_DATE_EPOCH`, `npm ci --ignore-scripts`, statische Binaries. Architekturen: **amd64 und arm64**.
- **.deb** (z. B. mit `nfpm`): Paket `daemonica` mit drei Binaries und gehärteten Units.
  - `postinst`: legt Benutzer/Gruppen `daemonica-web`, Verzeichnisse und Schlüsselmaterial an, aktiviert die Units, startet den Web-Dienst **nur im Setup-Modus an Loopback** und gibt den Hinweis auf `daemonica-admin bootstrap` aus.
  - `prerm`/`postrm`: Daten bleiben bei `remove` erhalten; nur bei `purge` (mit Warnhinweis) werden Daten gelöscht.
- **Signierung:** `.deb`, `SHA256SUMS` und apt-`Release` werden mit einem **vom Auftraggeber bereitgestellten Schlüssel** signiert (S2, falls nicht vorhanden). Ohne Schlüssel entstehen ausschließlich Artefakte mit dem Zusatz `-UNSIGNED-TESTONLY`. **Niemals** Signierschlüssel im Repo ablegen oder selbst als „Produktivschlüssel“ erzeugen.
- **Apt-Repository:** `scripts/make-apt-repo.sh` (z. B. mit `reprepro`) erzeugt ein signiertes Repo; zusätzlich werden die Artefakte einzeln als Release geliefert.
- **Update-Pfad:** `apt upgrade`; Datenbankmigrationen sind vorwärtsgerichtet mit automatischem Backup; Rollback = älteres `.deb` + Backup-Restore (in `docs/INSTALL.md` dokumentiert).
- **SBOM** (CycloneDX) für Go und npm bei jedem Release.

### 4.4 Abhängigkeitspolitik (Supply Chain)

- Standardbibliothek vor Drittpaketen. Jede neue Abhängigkeit: Begründung (Zweck, Lizenz, Wartungsstand, transitive Last, Alternativen) in `docs/DECISIONS.md`.
- Exakte Versionen (`go.sum`, `package-lock.json`); keine `postinstall`-Skripte; Pakete jünger als **14 Tage** nur bei dokumentiertem Security-Fix.
- Erlaubte Lizenzen: MIT, BSD, Apache-2.0, ISC, MPL-2.0. Keine GPL/AGPL-Bibliotheken im Binary.
- Keine CDNs, keine externen Fonts, keine Laufzeit-Downloads von Code.
- `make sec` führt mindestens `govulncheck`, `npm audit --omit=dev`, Lizenzprüfung und Secret-Scan aus.

---

## 5. Design und UX

### 5.1 Designsprache (abgeleitet aus Logo und Maskottchen)

Dunkles **„Terminal-Noir“** mit Neon-Akzenten: tiefes Violett-Schwarz als Grund, Verläufe von **Violett → Magenta/Pink** mit **Cyan** als technischem Akzent (Terminal-Prompt `>_`, Statuslampen am Server-Rack). Rote Dämonenhörner (Logo-„o“) und der kleine Dämonenschädel auf dem Ärmel sind Marken-Details.

- Formen: abgerundet (Panels 12–16 px, Controls 8 px), Rahmen mit zarter Verlaufslinie wie beim App-Icon.
- Motive: Server-Rack, Terminal-Cursor `>_`, Statuslampen.
- Ton: freundlich, leicht verspielt, aber sachlich in Arbeitsansichten.
- **Dichte Arbeitsansichten** (Tabellen, Logs, Editor, Terminal, Formulare) bleiben ruhig: keine Glow-Effekte hinter Text, Verläufe nur in Kopfzeilen, aktiver Navigation und Fokuszuständen.

### 5.2 Design-Tokens (verbindlich, Kontrast geprüft)

Alle Farben als CSS-Variablen; Kontrastwerte sind gegen `--bg-0/1/2` gemessen (WCAG-Kontrastverhältnis).

```css
:root {
  /* Flächen (Maskottchen-Hintergrund als Basis) */
  --bg-0: #15121E;          /* App-Hintergrund */
  --bg-1: #1C1829;          /* Panels, Karten */
  --bg-2: #241F35;          /* erhöhte Elemente, Hover */
  --border-subtle: #342D4A; /* dekorativ */
  --border-strong: #6F6596; /* Eingabefelder/Controls (≥ 3:1 auf bg-0/1/2) */

  /* Text */
  --text: #E8E6F7;          /* 15:1 auf bg-0 */
  --text-muted: #A9A3C7;    /* 7.7:1 */
  --text-faint: #8F88B0;    /* 5.2:1 auf bg-1; nur für Nebeninfos */

  /* Marken-Akzente */
  --violet-brand: #8B13FC;  /* NUR dekorativ/Verläufe (3.2:1) – nicht für Text */
  --violet-btn:   #7A0FE0;  /* Button-Füllung, weißer Text 7.1:1 */
  --violet-text:  #B57BFF;  /* Links/Text auf dunkel 6.4:1 */
  --magenta-brand:#F01070;  /* NUR dekorativ/Verläufe */
  --magenta-btn:  #C80A58;  /* Button-Füllung, weißer Text 5.8:1 */
  --magenta-text: #FF5C9E;  /* Text auf dunkel 6.4:1 */
  --cyan:         #10F0F0;  /* Fokusring, Terminal-Prompt, aktive Indikatoren (13:1) */
  --horn-red:     #D01050;  /* dekorativ */

  /* Status (nie allein Farbe: immer Icon + Text) */
  --success: #3DDC97;  --warning: #FFB84D;  --danger: #FF5470;  --info: #5AB8FF;

  /* Verläufe */
  --grad-brand: linear-gradient(90deg, #8B13FC 0%, #DC24AF 55%, #F01070 100%);
  --grad-edge:  linear-gradient(135deg, #8B13FC, #DC24AF 50%, #10C8F0);

  --radius-panel: 14px;  --radius-control: 8px;
  --focus-ring: 2px solid var(--cyan);  /* + 2px offset */
}
```

- **Primärer Button:** `--violet-btn` mit weißem Text (Hover heller). **Destruktive Aktion:** `--magenta-btn` mit weißem Text. **Sekundär:** transparent mit `--border-strong`.
- **Heller Modus (SOLL):** abgeleitete Variante mit denselben Rollen, z. B. `bg #FAF8FF`, `surface #FFFFFF`, `text #1B1530`, `muted #5B5478`, `violet #6A0FD0`, `magenta #B8084F`, `cyan-ink #00727A`, `border-strong #7A72A0`. Status-Farben für hell separat so wählen, dass AA erreicht wird. Standard ist **Dunkel** (unabhängig von `prefers-color-scheme`); die Auswahl ist pro Benutzer speicherbar.

### 5.3 Typografie

Inter (UI) und JetBrains Mono (Code, Terminal, Logs), beide **selbst gehostet** als `woff2` (OFL-Lizenz, Lizenztext beilegen). Fallback: `system-ui` bzw. `ui-monospace`. Basisschrift 15 px, Zeilenhöhe 1.5.

### 5.4 Branding-Assets

- Quelldateien (vom Auftraggeber): `assets/branding/daemonica-logo-transparent.png` (1672×941, transparent, Wortmarke „Daemonica“ mit Maskottchen und Server-Rack) und `assets/branding/daemonica-mascot.png` (1254×1254, App-Icon-Stil mit Neon-Rahmen).
- **MUSS:** Assets unverändert übernehmen (nur Skalierung/Zuschnitt/Kompression, z. B. WebP/PNG in mehreren Größen). Das Maskottchen wird **nicht** neu gezeichnet oder umgefärbt, es werden **keine zusätzlichen Posen generiert**; Variation entsteht nur über Größe, Platzierung und Rahmeneffekte.
- **Ableitungen:** Favicon (`.ico` + PNG 32/48/180/512), kompaktes Icon für die Sidebar (Zuschnitt aus dem Maskottchen), Logo für Login/Setup (groß).
- **Einsatz des Maskottchens:** Login, Setup-Assistent, Leerzustände, Lade-/Wartezustände (z. B. Neustart), Erfolgsmeldungen, 404/Fehlerseiten. **Nicht** in dichten Arbeitsansichten. Schutzraum um das Logo ≥ ¼ der Logohöhe, keine Verzerrung.

### 5.5 Layout und Navigation

- **Seitenleiste** (einklappbar) mit Gruppen:
  - Übersicht
  - Dienste & Jobs
  - System (Benutzer, SSH-Schlüssel, Netzwerk, Firewall mit Status/Regeln/Logs, Updates, Datenträger, Zeit & Host)
  - Werkzeuge (Terminal, Dateien, Logs, Prozesse, Paketmitschnitt)
  - Sicherheit (Audit-Log, Sitzungen, Passkeys, Einstellungen)
  - Phase 2 ergänzt: Checkliste, Monitoring, Alarme. Phase 3 ergänzt: Anwendungen.
- **Kopfzeile:** Hostname, Rollen-Badge, Sitzungs-/Step-up-Timer, Alarm-Glocke (Phase 2), Sprache, Theme, Benutzermenü. Im erhöhten Modus (root) zeigt eine **rote, nicht ausblendbare Leiste** den Zustand an.
- **Responsiv:** ≥ 1024 px voll; 768–1023 px kompakt; < 768 px nutzbar für Status, Dienste, Neustarts, Alarme (Terminal/Editor eingeschränkt, aber funktionsfähig).

### 5.6 Geführte Abläufe (Kern der Nutzbarkeit)

- **Wizard-Komponente:** Schrittanzeige, Zurück/Weiter, **Preflight-Prüfungen** (✓ / ⚠ / ✖ mit verständlicher Erklärung und Lösungsvorschlag), Box „Was passiert hier?“, Risikostufe farbcodiert (mit Text), **Plan-/Diff-Vorschau**, Zusammenfassung vor dem Anwenden, Bestätigungs-Timer-Dialog bei Aussperr-Risiko.
- **Einrichtungs-Checkliste** auf der Übersicht („Einrichtung abschließen: 3 von 7 Schritten“): gültiges Zertifikat, Allowlist gesetzt, zweiter Passkey, Firewall aktiv, Updates/Auto-Updates, geplante Backups bzw. Jobs usw.
- **Gefährliche Aktionen:** Konsequenz in einfachen Worten, bei destruktiven Aktionen „Name eintippen zum Bestätigen“.
- **Fachbegriffe** haben Tooltips/Kurzerklärungen; Leerzustände nennen den nächsten sinnvollen Schritt.

### 5.7 Barrierefreiheit und Internationalisierung

- **WCAG 2.2 AA:** vollständige Tastaturbedienung, sichtbarer Fokusring (`--focus-ring`), `prefers-reduced-motion`, Farbe nie alleiniger Informationsträger, Formularfelder mit Labels und Fehlertexten. Automatisierter `axe`-Test in den E2E-Tests.
- **i18n:** keine hartkodierten Texte; `de.json`/`en.json`, Pluralisierung und Formate über `Intl`; CI prüft fehlende Schlüssel. Serverseitige Fehler liefern stabile `code`-Werte, die im Frontend übersetzt werden.

---

## 6. Arbeitsweise, Qualität und Tests

### 6.1 Regeln für die Test-VM

1. Arbeite **ausschließlich** auf der bereitgestellten Debian-/Ubuntu-Test-VM (root). Erste Aktion: `/etc/os-release`, Ressourcen, Netz, Snapshot-Möglichkeit prüfen und in `docs/STATUS.md` festhalten. Fehlen Zugangsdaten → S2.
2. **Zielmatrix:** die zum Projektstart aktuell unterstützten Debian- und Ubuntu-LTS-Releases. Ermittle sie per Recherche und `/etc/os-release`, lege sie in `docs/DECISIONS.md` fest und teste mindestens auf der Test-VM; weitere Releases per VM/Container-Image, soweit verfügbar (KANN).
3. Vor riskanten Tests (Netzwerk, Firewall, fstab, SSH) einen **Snapshot** anfordern bzw. nutzen. Ist keiner möglich: nur mit Bestätigungs-Timer/Rollback testen und einen **zweiten Zugangsweg** (Konsole oder zweite SSH-Sitzung) offen halten.
4. Keine Produktivdaten, keine echten Geheimnisse. ACME **nur gegen Let’s-Encrypt-Staging**; Produktiv-ACME nur auf ausdrückliche Anweisung (S2).
5. Räume nach Tests auf und dokumentiere den Zustand der VM.

### 6.2 Meilensteine und Statusführung

Jede Phase besteht aus nummerierten Meilensteinen (§7–§9). `docs/STATUS.md` führt pro Meilenstein: Status, Tests (Anzahl/Ergebnis), offene Punkte und eine Tabelle **aller MUSS/SOLL-Anforderungen** mit Status (✓ erledigt / ⚠ teilweise / ✖ offen / – entfällt mit Begründung).

### 6.3 Definition of Done (pro Funktion)

- Funktion entspricht den Anforderungen und Abnahmekriterien.
- Autorisierung in Policy-Tabelle und Rollenmatrix hinterlegt; Autorisierungstests grün.
- Eingabevalidierung, Größen-/Zeitlimits, Fehlerbehandlung, Audit-Einträge vorhanden.
- Negativ-/Sicherheitstests vorhanden (z. B. Injection-Payloads, Pfadmanipulation).
- UI: i18n (de/en), a11y-Test, Leer-/Lade-/Fehlerzustände, geführte Abläufe bei riskanten Aktionen.
- Doku aktualisiert (`ARCHITECTURE.md`, ggf. `THREAT-MODEL.md`, `INSTALL.md`), OpenAPI aktuell.
- `make lint test sec` grün.

### 6.4 Teststrategie

| Ebene | Inhalt |
|---|---|
| Unit | Parser, Validierung, Policy, Zustandsmaschinen; Abdeckung ≥ 85 % in `auth`, `policy`, `rpc`, `files`, `pty`; gesamt ≥ 70 %. |
| Integration (Test-VM) | Helper-Operationen gegen echtes systemd/apt/ufw/Netzwerkstack mit Fixtures und Rollback-Prüfung. |
| E2E | Playwright mit **virtuellem WebAuthn-Authenticator** (CDP): Setup, Login, Step-up, alle Module, Rollen. |
| Autorisierung | Generierte Matrix: Endpunkt × Rolle × Step-up. |
| Fuzzing | Go-Fuzz für `authorized_keys`-Parser, Cron-/Kalender-Parser, Pfadnormalisierung, RPC-Decoder. |
| Sicherheitstests | CSRF, Origin, Sitzungsfixierung, WebAuthn-Replay, Step-up-Ablauf, Pfad-Traversal und Symlink-Races, Kommando-/Argument-/Unit-File-Injection in **allen** String-Parametern, Upload-Grenzfälle, WebSocket-Missbrauch, Rate-Limits. |
| Nicht-funktional | Grundlast (z. B. 50 parallele Sitzungen), Ressourcenverbrauch im Leerlauf (Ziel: < 100 MiB RAM Web-Prozess ohne Last). |

### 6.5 Sicherheitsaudit je Phase (D-11)

**Ablauf:** (1) Automatische Prüfwerkzeuge, (2) KI-Review nach festem Katalog, (3) Bericht `docs/security/AUDIT-PHASE-<N>.md`, (4) Behebung, (5) Re-Test.

**Werkzeuge (soweit installierbar; nicht Ausgeführtes wird mit Grund dokumentiert, nie stillschweigend übersprungen):** `go vet`, `staticcheck`, `golangci-lint`, `gosec`, `govulncheck`, `osv-scanner`, `gitleaks`, `npm audit --omit=dev`, `eslint` (+ Security-/React-Regeln), `tsc --noEmit`, `systemd-analyze security`, TLS-Prüfung (`testssl.sh`/`sslyze` oder `openssl s_client`), `lynis` auf der Test-VM (KANN), OWASP-ZAP-Baseline (KANN), `axe` (a11y).

**Prüfkatalog (je Eintrag: Ergebnis, Beleg, Status):**

| ID | Bereich | Prüfinhalt |
|---|---|---|
| SA-01 | Authentifizierung | WebAuthn-Konfiguration (UV, RP-ID, Origin, Challenge-Einmaligkeit), Bootstrap/Recovery-Tokens, keine Konto-Enumeration |
| SA-02 | Autorisierung | Policy-Vollständigkeit, Deny-by-default, Step-up-Bindung, Horizontal-/Vertikal-Eskalation |
| SA-03 | Sitzungen | Cookie-Flags, Rotation, Timeouts, Fixierung, Abmeldung, Gleichzeitigkeit |
| SA-04 | Web-Schicht | CSRF, XSS (inkl. Terminal/Logs/Dateinamen), CSP, Header, CORS, Clickjacking |
| SA-05 | Injection | Kommando-, Argument-, Pfad-, SQL-, Unit-File-, Header-Injection |
| SA-06 | Privilegientrennung | Socket-Rechte, `SO_PEERCRED`, Operations-Allowlist, kein generischer Exec, Worker-Credential-Wechsel |
| SA-07 | TLS und Netz | Protokolle/Cipher, Zertifikate, Allowlist-Durchsetzung, ACME-Fenster, offene Ports |
| SA-08 | Geheimnisse | Speicherung, Verschlüsselung, Logs, Prozesslisten, Dateirechte |
| SA-09 | Dateien/Terminal | Traversal, Symlink/TOCTOU, Upload/Download, PTY-Isolation, Ressourcenlimits |
| SA-10 | Audit | Vollständigkeit, Manipulationsschutz (Kettenprüfung), keine sensiblen Daten |
| SA-11 | Verfügbarkeit | Rate-Limits, Größenlimits, Timeouts, Ressourcenerschöpfung, Rollback-Timer |
| SA-12 | Härtung und Paketierung | systemd-Scores, Dateirechte, Maintainer-Skripte, Update-/Rollback-Pfad |
| SA-13 | Supply Chain | Abhängigkeiten, Lizenzen, SBOM, Build-Reproduzierbarkeit, Signierung, **Herkunft aller Paketquellen, Archive und Images (nur offizielle Quellen, D-19)** |
| SA-14 | Datenschutz | Keine Telemetrie, ausgehende Verbindungen nur wie konfiguriert |
| SA-15 | Netzwerkanalyse | Paketmitschnitt: Step-up, Limits (Dauer/Größe/Speicher), Sandbox des Erfassungsprozesses, speichersicherer Parser, Aufbewahrung und Löschung, Download-Schutz, Filter-Injection. Firewall-Logs: Log-/Ausgabe-Injection, Volumenlimits, keine externen Lookups |

**Zusatzprüfungen:** Phase 2 – Webhook-SSRF und DNS-Rebinding, Secret-Handling für SMTP/Webhook/API-Tokens, Sicherheit der Checklisten-Behebung (Rollback), Alarmflut/DoS. Phase 3 – Container-Härtung und Docker-Socket-Zugriff, nginx-/TLS-Konfiguration, RADIUS-Härtung, Netz-Exposition der Apps, Backup-Handling, Härtung beider Betriebsarten (nativ und Docker), Wirksamkeit und Aufräumen der automatisch angelegten Firewall-Regeln.

**Schweregrade und Gate-Regel:**
- *Kritisch/Hoch:* **MUSS** vor der Abnahme behoben und per Re-Test belegt sein.
- *Mittel:* Beheben **oder** dem Auftraggeber im Abnahmepaket als „Entscheidung nötig“ vorlegen. Die Risikoakzeptanz trifft nur der Auftraggeber, nie das KI-Modell.
- *Niedrig/Info:* Backlog mit Begründung.

**Berichtsformat je Befund:** ID, Titel, Schweregrad, betroffene Komponente/Datei, Beschreibung, Nachweis (Befehl/Test), Empfehlung, Status (offen/behoben/akzeptiert), Re-Test-Beleg.

### 6.6 Abnahmepaket und Phasen-Gate (D-15, S1)

Am Ende jeder Phase, **nach** Audit und Behebung, lieferst du:

1. Signiertes Release-Candidate-`.deb` (bzw. `-UNSIGNED-TESTONLY`) + `SHA256SUMS`.
2. `CHANGELOG.md`, `docs/STATUS.md` (Anforderungsstatus), Testbericht (Zahlen).
3. `docs/security/AUDIT-PHASE-<N>.md` inkl. Liste „Entscheidung nötig“.
4. `docs/acceptance/ACCEPTANCE-PHASE-<N>.md` mit **manueller Abnahme-Checkliste auf Deutsch** (frische VM → Installation → Bootstrap → Passkeys → je Modul 3–5 konkrete Prüfschritte → Rollenprüfung → Deinstallation/Rollback).
5. `docs/INSTALL.md`, bekannte Einschränkungen, alle neuen Annahmen/Entscheidungen seit dem letzten Gate.

Danach: **STOPP (S1).** Nachbesserungen aus der Abnahme erfolgen als Fix-Release innerhalb der Phase inklusive Mini-Audit der geänderten Teile. Die nächste Phase beginnt **erst nach ausdrücklicher Freigabe** („Phase N abgenommen“).

---

## 7. Phase 1 — Fundament und Kernverwaltung

**Voraussetzung:** keine. **Ergebnis:** abnahmefähiges Release (§6.6). Rollen- und Step-up-Details je Funktion: Anhang A.

### 7.0 Meilensteine

| ID | Inhalt |
|---|---|
| M1.0 | Fundament: Repo, Toolchain, `make`-Ziele, Paketierung, systemd-Units, RPC-Protokoll, Helper-Grundgerüst (Konten-DB, Grants, Policy, Audit), Web-Grundgerüst (TLS, Allowlist, Middleware, Header), WebAuthn (Enrollment/Login/Step-up), Bootstrap/Recovery, Setup-Assistent, UI-Shell (Layout, Theme, i18n, Branding), Konten-/Rollen-/Passkey-/Sitzungsverwaltung, Audit-Log, Plan→Apply→Confirm-Framework |
| M1.1 | Systemübersicht, Dienststatus, Logs, Prozesse |
| M1.2 | Benutzerverwaltung, SSH-Schlüsselverwaltung |
| M1.3 | Dateimanager, Editor, Up-/Download |
| M1.4 | Web-CLI |
| M1.5a | Netzwerkkonfiguration |
| M1.5b | Firewall: Status, Regelwerk, Verwaltung |
| M1.5c | Firewall-Logs |
| M1.5d | Paketmitschnitt (Packet Capture) |
| M1.6 | Aufgaben- und Jobplanung |
| M1.7 | Updates (apt), Datenträger/Mounts, Zeit/Hostname/Neustart |
| M1.8 | Gesamthärtung, E2E-Gesamttest auf frischer VM, Sicherheitsaudit Phase 1, Abnahmepaket |

### 7.1 M1.0 — Fundament

**Setup-Assistent** (nur im Setup-Modus, Zugang per Token, §3.3):
1. Token eingeben; Hinweis zum SSH-Tunnel falls nötig.
2. **Domain** festlegen; Preflight: DNS-Auflösung, Port-Verfügbarkeit.
3. **Zertifikat** wählen (eigenes / DNS-01 geführt / HTTP-01 bzw. TLS-ALPN-01), Ausstellung mit Live-Fortschritt.
4. **Netzfreigabe (Allowlist)**: vorgeschlagenes Client-Netz, Erklärung der Risiken einer öffentlichen Freigabe, Standard „nur freigegebene Netze“.
5. **Ersten Admin-Passkey** auf der Ziel-Domain registrieren; Zuordnung zum Linux-Benutzer (Dropdown, UID ≥ 1000 oder der Benutzer, der den Bootstrap ausgeführt hat); Aufforderung zum zweiten Passkey.
6. Zusammenfassung; Setup-Modus endet.

**Konten, Rollen, Passkeys** (Admin, Step-up): Konten anlegen (Name, Rolle, Linux-Benutzer) mit Einladungs-Token (einmalig, 60 min, nur einmal anzeigbar); Rolle ändern; Konto deaktivieren/löschen (letzter Admin nicht löschbar/degradierbar); Passkeys je Konto: Liste (Name, erstellt, zuletzt benutzt, synchronisiert/gerätegebunden), umbenennen, hinzufügen, entfernen (nie den letzten); Sitzungsliste und Sitzungen beenden.

**Einstellungen** (Admin, Step-up): Domain/TLS, Allowlist, Sitzungszeiten (im erlaubten Rahmen), Standardsprache, Upload-Limit. Allowlist-/TLS-Änderungen laufen über Plan→Apply→Confirm.

**Abnahmekriterien M1.0:** Frische Installation startet nur an Loopback; Bootstrap-Token funktioniert genau einmal; ohne gültigen Passkey ist keine API-Funktion erreichbar; Step-up-Ablauf nach 5 min erzwungen; Recovery per Konsole funktioniert und beendet alte Sitzungen; Allowlist blockiert nicht erlaubte IPs vor dem TLS-Handshake; Audit-Kette ist verifizierbar; Aussperr-Schutz greift (Test: Allowlist ohne eigene IP → Warnung + Auto-Rollback).

### 7.2 M1.1 — Systemübersicht, Dienste, Logs, Prozesse

**Systemübersicht (MUSS):** Hostname, OS/Kernel, Uptime, Load, CPU-Auslastung, RAM/Swap, Datenträger (Nutzung und Inodes je Mount), Netzwerk (Interfaces, Durchsatz live), Top-Prozesse, „Neustart erforderlich“, ausstehende Updates (gesamt/sicherheitsrelevant), fehlgeschlagene systemd-Units, letzte Anmeldungen, Zertifikatsablauf des Dashboards, Einrichtungs-Checkliste (§5.6). Live-Updates alle 2–5 s über **einen gemeinsamen Collector** (kein Polling-Sturm).

**Dienststatus (MUSS):**
- Liste aller Units (Typ service/timer/socket) mit Active/Sub-State, Enabled, Beschreibung, seit wann, Speicher; Suche und Filter.
- Aktionen: start, stop, restart, reload, enable, disable, mask, unmask. Detailansicht: Status, Journal des Dienstes, Unit-Datei (nur lesen), Abhängigkeiten.
- Umsetzung über **D-Bus** (`org.freedesktop.systemd1`), nicht durch Parsen von `systemctl`.
- **Geschützte Units:** `daemonica-*`, `ssh`/`sshd`, `systemd-*`: Aktionen nur Admin + Step-up + Warntext. `daemonica-helper` ist über die UI nicht stopp-/deaktivier-/maskierbar.

**Logs (MUSS):** journald-Abfrage mit Filtern (Unit, Priorität, Zeitraum, Boot, Freitext serverseitig), Follow-Modus per WebSocket, Export (Text/JSON) mit Zeilenlimit, neutralisierte Steuersequenzen. SOLL: Auswahl bekannter Dateien (z. B. `auth.log`, `syslog`) über eine Allowlist.

**Prozesse (MUSS):** Tabelle (PID, Benutzer, CPU %, RAM, Start, Befehl), Sortieren/Filtern, Signale senden (TERM, KILL, HUP, STOP, CONT) mit Bestätigung. Admin: alle Prozesse außer PID 1 und `daemonica-*`/sshd-Hauptprozess; Operator: nur Prozesse des zugeordneten Linux-Benutzers. Baumansicht KANN.

**Abnahmekriterien:** Werte stimmen mit `top`/`free`/`df` überein (Stichprobe); Dienst starten/stoppen/neu starten funktioniert; geschützte Units verlangen Step-up; Log-Follow zeigt neue Einträge < 2 s; Nur-Lesen kann weder Logs noch Prozesssignale nutzen.

### 7.3 M1.2 — Benutzer und SSH-Schlüssel

**Benutzerverwaltung (MUSS, Admin + Step-up für Änderungen):**
- Anzeige Linux-Benutzer (UID, Name, Beschreibung, Home, Shell, Gruppen, gesperrt, letzte Anmeldung, Passwortalter/-ablauf, Anzahl SSH-Schlüssel); System- und normale Benutzer getrennt (`UID_MIN/UID_MAX` aus `/etc/login.defs`); Gruppen und Mitglieder.
- Aktionen: **anlegen** (Assistent: Name validiert, Home, Shell aus `/etc/shells`, Gruppen; Standard: Passwort gesperrt, SSH-Schlüssel im Folgeschritt), ändern (Shell, Beschreibung, Gruppen, Ablauf), sperren/entsperren, löschen (mit/ohne Home, „Name eintippen“), Gruppen anlegen/ändern/löschen, **sudo-Mitgliedschaft** sichtbar und änderbar mit Warnhinweis, Passwort setzen (optional, über `chpasswd` via stdin, nie in argv/Logs; Mindestlänge 12 mit Stärkehinweis; „Änderung beim nächsten Login erzwingen“).
- **Schutz:** root nicht löschbar; Benutzer, die einem aktiven Dashboard-Konto zugeordnet sind, nur mit Zusatzbestätigung; Systembenutzer nur im „Erweitert“-Modus.
- Umsetzung über `useradd/usermod/userdel/groupadd/…` (argv) mit Dateisperren; keine direkte Bearbeitung von `/etc/passwd`.

**SSH-Schlüsselverwaltung (MUSS):**
- Je Linux-Benutzer `authorized_keys` anzeigen (Typ, Länge, **SHA256-Fingerprint**, Kommentar, Optionen). Pfade gemäß `AuthorizedKeysFile` aus `sshd -T`.
- Hinzufügen per Einfügen des Public Keys (Parser-Validierung). Erlaubt: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`, `ecdsa-sha2-*`, `sk-ecdsa-sha2-*`, `ssh-rsa` ≥ 3072 Bit; `ssh-dss` und kürzere RSA werden abgelehnt.
- Entfernen; geführte Optionen („Zugriff einschränken“: Quell-IP `from=`, `restrict`, `no-port-forwarding`, `command=` mit Warnhinweis); Prüfung/Korrektur der Rechte (`~/.ssh 0700`, `authorized_keys 0600`, Besitzer).
- **Host-Schlüssel des Servers** mit Fingerprints anzeigen (zum Abgleich beim ersten Verbindungsaufbau). Effektive `sshd`-Konfiguration (`sshd -T`) **nur lesen** (Änderungen später über die Phase-2-Checkliste).
- Operator darf Schlüssel seines zugeordneten Benutzers verwalten; Admin alle. Hinweis in der UI: Schlüsselpaare werden **auf dem Client** mit `ssh-keygen -t ed25519` erzeugt. Serverseitige Erzeugung ist KANN und standardmäßig nicht umgesetzt.

**Abnahmekriterien:** Benutzer anlegen/sperren/löschen inkl. Schutzregeln; sudo-Gruppe ändern erfordert Step-up; ungültige/zu schwache Schlüssel werden abgelehnt; Injection-Payloads in Namen/Kommentaren bleiben wirkungslos; Rechtekorrektur repariert absichtlich falsche Modi.

### 7.4 M1.3 — Dateimanager, Editor, Up-/Download

**Ansicht (MUSS):** Baum + Liste, Breadcrumbs, Sortieren/Filtern, Suche im aktuellen Ordner, Eigenschaften (Besitzer, Gruppe, Modus rwx + oktal, Größe, Zeiten, Symlink-Ziel), versteckte Dateien umschaltbar, **serverseitig paginierte** Verzeichnisse.

**Operationen (MUSS):** neue Datei/Ordner, umbenennen, verschieben/kopieren, löschen (rekursiv nur mit „Name eintippen“), `chmod` (Admin/Operator im Rahmen der Linux-Rechte), `chown` (nur Admin + Step-up). Archiv erstellen/entpacken KANN (dann mit Zip-Slip-Schutz).

**Berechtigungsmodell (MUSS):**
- Alle Operationen laufen im Worker **unter dem zugeordneten Linux-Benutzer** (§3.2 Nr. 6); die Linux-Rechte sind die Grenze.
- **„Als root“-Modus:** nur Admin, nur nach Step-up, zeitlich begrenzt (10 min), mit roter Leiste; jede schreibende Operation wird auditiert.
- **Hart gesperrt** (auch im root-Modus nicht les-/schreibbar): Daemonica-eigene Daten und Schlüssel (`/var/lib/daemonica*`, `/etc/daemonica*`, Schlüsseldateien, Helper-Socket-Verzeichnis).
- **Sensible Pfade** (z. B. `/etc/shadow`, `/etc/gshadow`, `/etc/ssh/ssh_host_*_key`, `~/.ssh/id_*`): zusätzliche Warnbestätigung, im Nicht-root-Modus ohnehin durch Linux-Rechte geschützt.

**Pfadsicherheit (MUSS):** serverseitige Kanonisierung, keine NUL-Bytes, fd-basierte Operationen (`openat2` mit `RESOLVE_*` wo möglich), Symlinks anzeigen und bei Schreiboperationen standardmäßig nicht folgen, TOCTOU-sicher; Race-Tests (Symlink-Austausch während der Operation).

**Editor (MUSS):**
- CodeMirror 6, Syntax-Highlighting (conf, ini, yaml, json, toml, sh, py, js/ts, md, sql, xml, nginx, systemd-Unit, crontab u. a.), Suchen/Ersetzen, Zeilennummern, Umbruch, Einrückung, Erhaltung von Zeilenenden (LF/CRLF), UTF-8; Binärdateien werden nicht im Editor geöffnet (Download anbieten); Größenlimit 5 MiB.
- **Speichern:** atomar (temp + `rename`), erhält Besitzer/Modus/ACL/xattr; **optimistische Nebenläufigkeit** (Hash/mtime-Vergleich, bei Konflikt Diff-Dialog); Warnung bei ungespeicherten Änderungen; ohne Schreibrecht klare Meldung („Datei gehört root – Admin kann als root bearbeiten“).
- SOLL: Bei Dateien unter `/etc` automatische Vorversion im Helper-Backup (30 Tage/20 Versionen) mit „Vorherige Version wiederherstellen“.
- SOLL: **Validierung** für bekannte Dateien vor dem Speichern: `sshd_config` (`sshd -t`), sudoers (`visudo -cf`; bei Fehler Speichern blockiert), `nginx -t`, systemd-Units (`systemd-analyze verify`), `fstab` (`findmnt --verify`).

**Upload (MUSS):** Drag & Drop, mehrere Dateien, Fortschritt, Abbruch; Streaming ohne Voll-Puffer; Limit konfigurierbar (Standard 1 GiB je Datei); Platzcheck vorab; Standardmodus `0640` (im Dialog änderbar), Besitzer = zugeordneter Benutzer; Überschreiben nur nach Bestätigung; SHA-256 im Audit.

**Download (MUSS):** Streaming mit Range-Unterstützung, `attachment` + `nosniff`, einmalige Token-URL (60 s). Ordner als ZIP/TAR-Stream KANN (mit Größen-/Zeitlimit).

**Rollen:** Nur-Lesen ✖; Operator und Admin ✔ im Rahmen der Linux-Rechte.

**Abnahmekriterien:** Traversal-/Symlink-/NUL-Tests bestehen; Datei bearbeiten → Konflikt erkennen → speichern; Rechte bleiben erhalten; Upload 1 GiB ohne RAM-Spitze; root-Modus nur nach Step-up; Zugriffe auf hart gesperrte Pfade werden abgelehnt und auditiert.

### 7.5 M1.4 — Web-CLI

**Funktion (MUSS):** xterm.js im Browser, PTY im Helper-Worker, Transport per WebSocket (Ticket, Origin-Check). Mehrere Tabs (Standard max. 5 je Konto), Resize, Kopieren/Einfügen (Bracketed Paste an), Suche im Scrollback, UTF-8, `TERM=xterm-256color`, Login-Shell des zugeordneten Benutzers.

**Modi (D-09):**
1. **Standard-Shell:** Worker unter dem zugeordneten Linux-Benutzer mit **gesetztem `no_new_privs`** → `sudo`, `su` und setuid-Programme sind wirkungslos. Für Operator und Admin.
2. **Erhöhter Modus (nur Admin, Step-up bei jedem Öffnen):** wahlweise (a) **root-Shell** oder (b) **Benutzer-Shell mit sudo** gemäß sudoers (`no_new_privs` aus). Rote, nicht ausblendbare Kopfzeile „ERHÖHT“; maximale Dauer 30 min, danach Beendigung (neues Step-up nötig).

**Sicherheit und Betrieb (MUSS):**
- Idle-Timeout 15 min (konfigurierbar); sofortiges Beenden bei Sitzungsende, Rollenentzug, Kontosperrung oder wenn die Quell-IP nicht mehr in der Allowlist ist.
- SOLL: Jede Terminal-Sitzung läuft in einer transienten systemd-Scope mit `TasksMax`/`MemoryMax`; beim Sitzungsende werden alle Prozesse beendet (SIGHUP, nach 5 s SIGKILL). Option „Hintergrundprozesse beibehalten“ KANN, Standard aus.
- Durchsatz-Limit gegen DoS; Wiederverbindung kurzer Abbrüche (2 min, 256 KiB Puffer) KANN.
- Audit: Start, Ende, Modus, Dauer, Quell-IP (keine Eingaben).
- Kein Dateitransfer über das Terminal. Nur-Lesen ✖.

**Abnahmekriterien:** Im Standardmodus schlägt `sudo` fehl; erhöhter Modus nur nach Step-up und endet nach Timeout; Sitzungsende beendet Prozessbaum; Allowlist-Änderung kappt Terminals; Origin-Verstöße werden abgewiesen.

### 7.6 M1.5a–d — Netzwerk, Firewall, Firewall-Logs und Paketmitschnitt

#### M1.5a — Netzwerkkonfiguration

**Backend-Erkennung (MUSS):** Aktiver Netzwerkmanager wird erkannt: **netplan** (inkl. Renderer networkd/NetworkManager), **ifupdown** (`/etc/network/interfaces*`), **NetworkManager** (`nmcli`), **systemd-networkd**. Schreibzugriff mindestens für netplan und ifupdown (MUSS), NetworkManager und systemd-networkd (SOLL). Bei nicht unterstützten oder gemischten Setups: nur Anzeige mit Erklärung.

**Anzeige (MUSS):** Interfaces (Status, MAC, MTU, Adressen v4/v6, Geschwindigkeit), Routen, DNS-Konfiguration, Gateway, Hostname/Domain, **lauschende Ports mit zugehörigem Prozess** („Offene Ports“).

**Konfiguration (Admin, Step-up, Plan→Apply→Confirm):** DHCP/statisch (v4/v6), Gateway, DNS-Server und Suchdomänen, MTU, zusätzliche Adressen, statische Routen. VLAN/Bridge/Bond: Anzeige MUSS, Anlegen KANN.
- **Aussperr-Schutz:** Betrifft die Änderung das Interface oder die Route der aktuellen Sitzung, gilt Warnstufe Rot. Nach dem Anwenden hat der Admin 90 s, in einer **neuen Verbindung** zu bestätigen; sonst automatisches Rollback auf die gesicherte Konfiguration (Helper-Timer, §3.2 Nr. 10). Die UI zeigt bei geänderter IP die neue URL an.
- Syntaxvalidierung und Diff-Vorschau vor dem Anwenden; Sperre gegen parallele Änderungen.

#### M1.5b — Firewall: Status, Regelwerk, Verwaltung

**Firewall-Status (MUSS):**
- Erkanntes Backend (ufw / nftables / iptables-nft / firewalld), aktiv/inaktiv, **ob beim Neustart aktiv** (persistent), Standardrichtlinien (eingehend/ausgehend/weitergeleitet), Anzahl Regeln, IPv6-Abdeckung, Logging-Level, Zeitpunkt und Benutzer der letzten Änderung (aus dem Audit-Log), **Regel-Zähler** (Pakete/Bytes je Regel, soweit das Backend sie liefert).
- **Status-Ampel** mit Erklärung in einfacher Sprache: Rot = Firewall inaktiv oder eingehende Standardrichtlinie „erlauben“; Gelb = aktiv, aber Hinweise (z. B. kein IPv6-Schutz, Logging aus, Regeln für nicht mehr lauschende Ports); Grün = aktiv, restriktive Standardrichtlinie, keine Auffälligkeiten.
- SOLL: **Erreichbarkeits-Ansicht** — lauschende Ports (Prozess, Bindeadresse) gegenüber der Firewall-Wirkung (erlaubt / blockiert / ungeschützt) mit verständlichen Hinweisen.

**Regelwerk (MUSS):**
- **ufw (verwaltetes Backend):** nummerierte Regeln mit **Klartext-Erklärung je Regel** („Erlaubt eingehend TCP 22 von überall“), Quelle/Ziel, Interface, Kommentar und Zähler. Regel hinzufügen (geführt: Dienstvorlage oder Port/Protokoll, Quelle alle/CIDR, allow/deny/limit), löschen, Logging-Level, aktivieren/deaktivieren. Von Daemonica verwaltete Regeln (Kommentar `daemonica:<app>:<zweck>`, siehe §9.1) sind markiert.
- **Rohansicht (nur lesend):** `nft list ruleset` bzw. `iptables-save`, durchsuchbar, mit Zählern, Export als Textdatei. Ist `firewalld` aktiv, ist alles nur lesend mit Hinweis. Export/Import des ufw-Regelwerks (Text) KANN.
- Beim Aktivieren werden **automatisch Regeln für den SSH-Port (aus `sshd -T`) und den Dashboard-Port** vorgeschlagen und per Pflichtbestätigung übernommen; Bestätigungs-Timer greift. Reset nur Admin + Step-up + „Name eintippen“.
- Fehlt `ufw`: Assistent „Firewall einrichten“ installiert `ufw` (nach Bestätigung) mit sicheren Defaults (eingehend verweigern, ausgehend erlauben).
- Alle Änderungen laufen über Plan → Apply → Confirm mit Aussperr-Schutz (§3.2).

#### M1.5c — Firewall-Logs

- **Quelle:** Kernel-Logeinträge der Firewall (ufw-Präfix `[UFW …]` bzw. nft-`log`-Präfixe) aus journald; serverseitig in Felder geparst: Zeit, Aktion (allow/block/audit), Richtung, Interface ein/aus, SRC, DST, PROTO, SPT, DPT, Flags, Länge.
- **Ansicht (MUSS):** Tabelle mit Filtern (Zeitraum, Aktion, Quell-/Ziel-IP bzw. CIDR, Port, Protokoll, Interface) und Freitext; **Live-Follow** per WebSocket mit Raten-Limit (Hinweis „N Einträge übersprungen“); Export (CSV/JSON) mit Zeilenlimit (z. B. 10.000 je Abfrage).
- **Auswertung (SOLL):** Top blockierte Quellen, Top Zielports, Verlauf über die Zeit, Anzahl je Aktion.
- **Schnellaktion (Admin, Step-up):** „Quelle blockieren“ erzeugt einen Plan für eine Deny-Regel (Plan → Apply → Confirm). Eigene Sitzungs-IP, Allowlist-Netze und der SSH-/Dashboard-Zugang sind davor geschützt.
- **Logging steuern (MUSS):** Level aus/low/medium/high/full mit Erklärung zu Datenmenge, Plattenplatz und Datenschutz (IP-Adressen sind personenbezogene Daten). Ist Logging aus, zeigt die Ansicht einen Assistenten zum Aktivieren (Standard „low“); bei „high/full“ Warnung. Verlorene Einträge durch journald-Ratenbegrenzung werden, soweit erkennbar, angezeigt.
- **Datenschutz:** Keine externen Lookups (kein GeoIP, kein externes Reverse-DNS); lokales Reverse-DNS ist optional und standardmäßig aus.
- **Sicherheit:** Alle Felder sind untrusted (Log-Injection): nur geparste, validierte Felder werden angezeigt, Rohzeilen ausschließlich als Text.
- **Rollen:** Admin ✔, Operator ✔, Nur-Lesen ✖ (Anhang A).

#### M1.5d — Paketmitschnitt (Packet Capture)

**Zweck und Zugriff (MUSS):** Diagnose von Netzwerkproblemen und Sicherheitsvorfällen. **Nur Admin, Step-up bei jedem Start**, vollständig auditiert (ohne Inhalte). Vor dem Start muss der Admin einen Warnhinweis bestätigen: Mitschnitte können vertrauliche und personenbezogene Daten enthalten (bei unverschlüsselten Protokollen z. B. Zugangsdaten und Inhalte); Einsatz nur im Rahmen der eigenen Befugnisse.

**Assistent (MUSS):**
1. **Zweck-Vorlage** (z. B. „Verbindungsproblem zu einem Host“, „Wer greift auf Port X zu?“, „DNS-Verkehr“, „DHCP“, „Allgemein, nur Kopfdaten“).
2. **Interface** aus der Kernel-Liste (Validierung, Namens-Regex `^[A-Za-z0-9_.:-]{1,15}$` und Existenzprüfung).
3. **Filter-Builder** (Protokoll, Host/Netz, Port(e), Richtung); der BPF-Ausdruck wird serverseitig erzeugt. Ein **freier BPF-Ausdruck** ist nur unter „Erweitert“ erlaubt, mit strikter Zeichen-Allowlist, ohne führendes `-`, ohne Optionen, plus Syntaxprüfung (Kompilier-Test); er wird immer als **ein einziges argv-Element** übergeben.
4. **Limits:** Dauer (Standard 5 min, max. 30 min), Paketanzahl (Standard 100.000), Dateigröße (Standard 100 MiB, max. 1 GiB), **Snaplen Standard 96 Byte (nur Header)**; „Volle Pakete“ nur unter „Erweitert“ mit zusätzlicher Warnung; Promiscuous-Modus Standard **aus**.
5. **Standardausschluss des Dashboard-Verkehrs** (`not tcp port <Dashboard-Port>`), damit die Live-Ansicht keine Rückkopplung erzeugt; abschaltbar.

**Technische Umsetzung (MUSS):**
- **Erfassung:** `tcpdump` (oder gleichwertig) nur zur **Erfassung** (pcap-Strom auf stdout, keine Protokoll-Dissektion) als **eigener stark eingeschränkter Prozess** in einer transienten systemd-Unit `daemonica-capture-<id>`: unprivilegierter Benutzer mit nur `CAP_NET_RAW` (`CAP_NET_ADMIN` nur bei Promiscuous), `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_PACKET AF_UNIX`, `SystemCallFilter`, `MemoryMax`, `RuntimeMaxSec` gleich dem Dauerlimit. Der Helper nimmt den Strom entgegen, **erzwingt alle Limits** (Dauer, Pakete, Größe, freier Speicher) und schreibt die Datei.
- **Live-Zusammenfassung:** durch einen **eigenen, speichersicheren Go-Parser** (Ethernet/VLAN, ARP, IPv4/IPv6, TCP/UDP/ICMP(v6); DNS-Namen KANN): Zeit, Quelle, Ziel, Protokoll, Länge, Flags/Info. Keine Payload-Anzeige im Standard; eine Hex-Ansicht der Nutzdaten ist KANN (nur bei vollen Paketen, mit Warnung).
- **Darstellung:** WebSocket mit Raten-Limit (max. 500 Zeilen/s, Hinweis „N Pakete nicht angezeigt“), Pause, Ansichtsfilter, Client-Puffer max. 10.000 Zeilen; alle Felder als Text rendern. SOLL: Statistik (Protokollverteilung, Top-Talker, Paket-/Byte-Raten).
- Es läuft **höchstens eine** Erfassung gleichzeitig; bei weniger als 10 % freiem Speicher wird abgebrochen.
- Abhängigkeit: `tcpdump` als `Recommends` im `.deb`; fehlt es, bietet der Assistent die Installation an (Admin, Step-up).

**Speicherung und Aufbewahrung (MUSS):** `/var/lib/daemonica-helper/captures/<id>.pcap` (`0600 root`), Metadaten in der Helper-Datenbank, Gesamtlimit (Standard 1 GiB), **automatische Löschung nach 24 h** (konfigurierbar bis max. 7 Tage), „Alle löschen“. Download als `.pcap` (`attachment`, einmalige Token-URL 60 s, **Step-up**), Löschen durch Admin. Verschlüsselung im Ruhezustand KANN.

**Rollen:** ausschließlich Admin (Anhang A).

**Abnahmekriterien M1.5:**
- *Netzwerk:* Fehlkonfiguration (falsches Gateway) wird nach 90 s ohne Bestätigung automatisch zurückgerollt und die VM bleibt erreichbar; „Offene Ports“ stimmt mit `ss` überein.
- *Firewall-Status/Regelwerk:* Ampel zeigt bei inaktiver Firewall Rot; Zähler stimmen mit `nft list ruleset` überein; Klartext-Erklärungen der ufw-Regeln sind korrekt; Firewall-Aktivierung sperrt SSH/Dashboard nicht aus.
- *Firewall-Logs:* Eine Testverbindung auf einen blockierten Port erscheint in < 3 s mit korrekten Feldern in der Live-Ansicht; Filter funktionieren; manipulierte Log-Präfixe/Felder (Injection-Payloads) werden nicht interpretiert; die Aktivierung des Loggings per Assistent funktioniert.
- *Paketmitschnitt:* Start nur mit Step-up; alle Limits greifen (Dauer, Größe, Pakete, Speicher); schädliche Filter (z. B. `-w /etc/passwd`, `; id`, `$(…)`, Optionstricks) werden abgewiesen; der Erfassungsprozess läuft ohne root und ohne Schreibzugriff außerhalb seines Pfads (per `systemctl show` belegt); der Download ist eine gültige `.pcap`-Datei (mit `tcpdump -r` lesbar); abgelaufene Mitschnitte werden gelöscht; Operator und Nur-Lesen werden abgewiesen; der Dashboard-Verkehr ist standardmäßig ausgeschlossen.

### 7.7 M1.6 — Aufgaben und Jobplanung

**Übersicht (MUSS):** alle geplanten Aufgaben: systemd-Timer (Unit, nächster/letzter Lauf, Ergebnis), cron (`/etc/crontab`, `/etc/cron.d/*`, `cron.{hourly,daily,weekly,monthly}`, Benutzer-Crontabs). `at`-Jobs KANN.

**Verwaltete Jobs (MUSS):** Von Daemonica angelegte Jobs sind **systemd-Service + Timer** mit Präfix `daemonica-job-` in `/etc/systemd/system/` (Metadaten im Helper). Assistent:
- Name/Beschreibung; **Befehl** als Programm + Argumentliste oder Skriptpfad (Modus „Shell-Befehl“ nur unter „Erweitert“ mit Warnung); **Benutzer** (Standard der zugeordnete Benutzer; andere Benutzer nur Admin; `root` nur Admin + Step-up);
- **Zeitplan-Builder** (stündlich/täglich/wöchentlich/monatlich/Intervall/Kalenderausdruck) mit Klartext-Vorschau und **nächsten 5 Ausführungen** (`systemd-analyze calendar`), Zeitzone, `Persistent`, `RandomizedDelaySec`;
- Timeout (Standard 1 h), Umgebung, Arbeitsverzeichnis, **Härtungs-Voreinstellung** („Standard sicher“: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict` mit wählbaren Schreibpfaden, `ProtectHome` u. a.), Ressourcenlimits;
- Ausgabe in journald; Aktionen: jetzt ausführen, aktivieren/deaktivieren, bearbeiten, duplizieren, löschen; Verlauf der letzten 20 Läufe (Start, Dauer, Exit-Code, Journal-Auszug).

**Cron (SOLL):** Anlegen/Bearbeiten/Löschen von Einträgen in Benutzer-Crontabs mit Syntaxprüfung und Vorschau der nächsten Läufe; „In systemd-Timer umwandeln“ KANN.

**Sicherheit:** Befehle nie im Web-Prozess ausführen; Unit-Namen per Allowlist-Regex; Schutz vor Unit-File-Injection (Zeilenumbrüche, `%`-Specifier maskieren); Argumente werden nicht durch eine Shell interpretiert.
**Rollen:** Operator: ausführen und aktivieren/deaktivieren; Admin: alles; Nur-Lesen: Ansicht.

**Abnahmekriterien:** Job anlegen → Timer läuft zur geplanten Zeit → Verlauf zeigt Exit-Code und Log; Injection-Payloads (`; rm`, `%n`, Zeilenumbrüche) bleiben wirkungslos; Härtungsoptionen sind in `systemctl show` sichtbar.

### 7.8 M1.7 — Updates, Datenträger, Zeit und Host

**Updates (apt, MUSS):**
- `apt update` mit Quellenfehlern, Liste aktualisierbarer Pakete (installiert → verfügbar, **Sicherheitsflag**), Installation „alle / nur Sicherheit / Auswahl“ mit Live-Fortschritt und Log; Behandlung der dpkg-Sperre; Anzeige „Neustart erforderlich“; SOLL `needrestart`-Hinweis (Dienste neu starten).
- **Automatische Sicherheitsupdates:** Status und geführte Einrichtung von `unattended-upgrades` (nur Security, optionaler Auto-Reboot mit Uhrzeit), Ergebnis-Log.
- Paket suchen/installieren/entfernen (Admin + Step-up); vor Entfernen **Simulation** (`-s`) zeigen und Zusatzentfernungen bestätigen lassen. Paketquellen **nur anzeigen** (inkl. deb822); in Phase 3 fügen ausschließlich Anwendungsmodule Quellen mit gepinntem Schlüssel hinzu (§9.1). Umsetzung `noninteractive`, Konfigurationsdateien standardmäßig behalten (`--force-confold`) mit Hinweis auf Konflikte; Paket-Holds KANN.

**Datenträger und Mounts (MUSS):**
- Blockgeräte (`lsblk`-Daten: Größe, Typ, Dateisystem, UUID, Mountpunkt, Modell), Belegung/Inodes, Mounts (Liste). LVM/RAID-Anzeige und SMART (falls `smartctl` vorhanden) KANN.
- mount/unmount (Admin + Step-up; belegte/kritische Mounts mit Meldung), **`fstab` strukturiert bearbeiten** (UUID bevorzugt, Optionsvorlagen wie `noexec,nosuid,nodev`, `nofail`-Empfehlung), Validierung (`findmnt --verify`), Backup, Bestätigungs-Timer.
- **Kein** Partitionieren/Formatieren (Nicht-Ziel).

**Zeit, Host, Power (MUSS):** Zeitzone (Liste), NTP-Status und -Schalter (timesyncd/chrony), Hostname (static/pretty) mit konsistenter `/etc/hosts`-Behandlung, Neustart/Herunterfahren (Admin + Step-up + „Name eintippen“, optional Verzögerung und Abbruch). Die UI wartet danach und verbindet automatisch neu.

**Abnahmekriterien:** Sicherheitsupdates auf der VM installieren; `unattended-upgrades` einrichten und per Trockenlauf prüfen; fehlerhafte `fstab` wird vor dem Speichern abgelehnt; Neustart-Fluss reconnectet.

### 7.9 M1.8 — Abschluss Phase 1

Gesamthärtung und Review; **E2E-Gesamttest auf frischer VM** (Installation aus `.deb` → Bootstrap → Setup → Passkeys → alle Module → Rollenprüfung); Sicherheitsaudit gemäß §6.5; Abnahmepaket gemäß §6.6; **STOPP (S1)**. In das Abnahmepaket gehört außerdem die Liste aller Annahmen (§10) zur Bestätigung durch den Auftraggeber.

---

## 8. Phase 2 — Sicherheits-Checkliste, Monitoring und Alarmierung

**Voraussetzung:** Phase 1 ausdrücklich abgenommen (S1). Die Mechanismen aus Phase 1 (Helper-Operationen, Plan→Apply→Confirm, Audit, Rollenmodell) werden wiederverwendet.

### 8.0 Meilensteine

| ID | Inhalt |
|---|---|
| M2.0 | Rahmen: Check-Engine, Metrik-Speicher, Regel-Engine-Gerüst, Benachrichtigungs-Gerüst, neue Policy-Einträge |
| M2.1 | Sicherheits-Checkliste inkl. Behebung per Klick |
| M2.2 | Collector, Speicher mit Rollups, Graphen |
| M2.3 | Regel-Engine: statisch → zusammengesetzt → dynamisch |
| M2.4 | Benachrichtigungskanäle: Webhook, Mail, API |
| M2.5 | Alarm-Center, Regel-Assistent, Vorlagen |
| M2.6 | Integration (Checkliste → Alarme, Job-Fehler → Alarme), Härtung, Audit Phase 2, Abnahmepaket (**STOPP S1**) |

### 8.1 Sicherheits-Checkliste (M2.1)

**Zweck:** Vergleich der aktuellen Serverkonfiguration mit bekannten Best Practices und Sicherheitsempfehlungen; bei Abweichungen Hinweis, Alarmierung und geführte Behebung.

**Aufbau einer Prüfung (MUSS):** `id` (z. B. `SSH-001`), Titel (de/en), Kategorie, Schweregrad (kritisch/hoch/mittel/niedrig/info), Begründung in einfacher Sprache („Warum ist das wichtig?“), **read-only Prüfung** (Soll/Ist), Behebungsplan (Dateidiff bzw. konkrete Änderungen), Rückgängig-Information, Risikohinweis (z. B. Aussperr-Risiko), Referenzen.
- **Referenzen** auf CIS-Benchmarks (Debian/Ubuntu), BSI (z. B. Baustein SYS.1.3 Linux) und Distributionsdokumentation erfolgen **nur als Verweis** (Abschnittstitel/-nummer). Benchmark-Texte werden **nicht kopiert**; Formulierungen sind eigenständig (Urheberrecht/Lizenz).

**Mindestumfang bei Abschluss: ≥ 60 Prüfungen**, verteilt auf:

| Kategorie | Beispiele |
|---|---|
| SSH-Daemon | `PermitRootLogin`, `PasswordAuthentication`, `PubkeyAuthentication`, `X11Forwarding`, `MaxAuthTries`, `LoginGraceTime`, `AllowTcpForwarding`, `ClientAlive*`, moderne KEX/Cipher/MAC, Host-Key-Typen und -Rechte |
| Konten und Authentifizierung | zusätzliche UID-0-Konten, leere Passwörter, Passwortrichtlinie (`pam_pwquality`), Alterung, sudo (`NOPASSWD`, `!authenticate`), `su`-Beschränkung, inaktive Konten |
| Netzwerk und Firewall | Firewall aktiv, Default-Policy, offene Ports gegen Erwartung, IPv6-Handhabung, sysctl (`rp_filter`, Redirects, Source-Routing, SYN-Cookies, ICMP-Broadcast) |
| Kernel und System | ASLR, `dmesg_restrict`, `kptr_restrict`, `ptrace_scope`, Core-Dumps, `fs.protected_*`, `suid_dumpable` |
| Dateisystem und Rechte | Rechte von `/etc/passwd`, `shadow`, `gshadow`, SSH-Dateien; world-writable Dateien/Verzeichnisse ohne Sticky-Bit (Scan mit Limit); Mount-Optionen von `/tmp`, `/var/tmp`, `/dev/shm`, `/home`; umask-Defaults |
| Updates und Pakete | ausstehende Sicherheitsupdates, `unattended-upgrades`, Neustart erforderlich, Paketquellen signiert/https, unsichere Altpakete (telnet, rsh, ftp), **End-of-Life-Prüfung** der Distribution |
| Dienste | unnötige lauschende Dienste, Zeitsynchronisation, cron/at-Zugriff, journald-Persistenz/Rotation, Brute-Force-Schutz (fail2ban/CrowdSec vorhanden) |
| Logging und Audit | persistentes Journal, Log-Rotation, `auditd` und Grundregeln (Empfehlung) |
| **Daemonica-Selbstprüfung** | TLS-Zertifikat gültig/Restlaufzeit, Allowlist ≠ `0.0.0.0/0`, ≥ 2 Passkeys je Admin, Audit-Kette intakt, systemd-Scores, Sitzungszeiten im Rahmen, Socket-/Dateirechte, Daemonica-Version aktuell |

**Ausführung und Ergebnisse (MUSS):**
- Manuell und geplant (täglich, konfigurierbar); ressourcenschonend (nice/ionice, Zeit- und Mengenlimits); alle Prüfungen idempotent und nur lesend.
- Status je Prüfung: **bestanden / fehlgeschlagen / nicht anwendbar / nicht prüfbar (Fehler) / akzeptiertes Risiko**. „Akzeptiertes Risiko“ verlangt Begründung und **Ablaufdatum** (max. 365 Tage), ist auditiert und nur durch Admin setzbar.
- Gewichteter Score und Trend, Historie (30 Läufe detailliert, danach aggregiert), Filter nach Kategorie/Schweregrad/Status, Detailseite mit „Warum?“, Ist/Soll, **„Beheben“**.
- Export JSON und Markdown.

**Behebung per Klick (D-16, MUSS):**
1. **Plan:** exakte Änderungen (Dateidiff/Befehlsliste), betroffene Dateien und Dienste, Auswirkung in einfacher Sprache, Neustart/Reload nötig?, Risikohinweis.
2. **Bestätigung** durch Admin (**Step-up** bei Risiko ≥ mittel sowie immer für SSH, Firewall, Netzwerk, PAM, sudo).
3. **Anwendung** im Helper: Backup → atomar schreiben → Validierung (z. B. `sshd -t`) → aktivieren (reload); bei Aussperr-Risiko mit **Bestätigungs-Timer**.
4. **Nachprüfung** (Re-Check) mit Ergebnisanzeige.
5. **Rückgängig** bis 30 Tage über das Backup.
- Mehrfachauswahl erzeugt **einen kombinierten Plan** mit serieller Ausführung und Abbruch bei Fehler.
- **Keine automatische Behebung ohne Klick.**
- **Alarmierung:** Neue oder schlimmer gewordene Abweichungen erzeugen ein Ereignis für das Alarmsystem (Quelle `checklist`, Schweregrad-Mapping).

**Abnahmekriterien:** ≥ 60 Prüfungen laufen auf der Test-VM; absichtlich unsichere Einstellungen (z. B. `PermitRootLogin yes`) werden erkannt; Behebung mit Vorschau → Anwendung → Re-Check grün → Rückgängig stellt den Ausgangszustand her; SSH-Fix sperrt nicht aus (Validierung + Timer); akzeptiertes Risiko läuft ab.

### 8.2 Monitoring (M2.2)

**Collector (MUSS):** Standardintervall 15 s (einstellbar 5–300 s). Speicherung in `metrics.db` (SQLite, Besitzer `daemonica-web`) mit **Rollups**: Rohdaten 48 h, 1-Minuten-Werte 30 Tage, 15-Minuten-Werte 400 Tage (Defaults konfigurierbar); Gesamtgrößenlimit (Standard 1 GiB) mit automatischer Bereinigung; gebündelte Schreibvorgänge.

**Metrik-Katalog (MUSS):** CPU (Nutzung je Modus), Load 1/5/15, RAM/Swap, Datenträger (Belegung, Inodes, I/O), Netzwerk (Bytes, Fehler je Interface), Uptime, Prozess-/Zombie-Anzahl, systemd (Anzahl fehlgeschlagener Units, Status je überwachter Unit), Anmeldefehler (aus journald), ausstehende (Sicherheits-)Updates, Neustart erforderlich, Zertifikats-Restlaufzeit, Checklisten-Score/Fehlerzahl, Daemonica-Eigenmetriken (Sitzungen, Fehlerquote, Helper-RPC-Latenz).

**Benutzerdefinierte Prüfungen (SOLL):** TCP-Port, HTTP(S) (Statuscode, Latenz, Zertifikatsablauf, Text-Teilstring), systemd-Unit, Dateialter/-größe (Pfad-Allowlist). **Keine** beliebigen Befehle. **SSRF-Schutz:** Ziele nur explizit durch Admin (Step-up); private, Link-Local- und Metadaten-Adressen (z. B. `169.254.169.254`) nur per ausdrücklicher Freigabe; Prüfung nach DNS-Auflösung (Rebinding-sicher), keine Redirects.

**Darstellung (MUSS):** Graphen mit Zeitbereichen 1 h/6 h/24 h/7 d/30 d/frei, adaptive Auflösung, Schwellen-Overlay und Alarmmarker (uPlot).

### 8.3 Regelwerk (M2.3)

**Regel (MUSS):** `id`, Name, Beschreibung, Schweregrad (info/warning/critical), Typ, Bedingung, `for` (Mindestdauer), Labels, Kanäle, Wiederholungsintervall, aktiv/inaktiv, Runbook-Text.

| Typ | Beschreibung |
|---|---|
| **Statisch** | Metrik + Filter, Operator, Schwellwert, Aggregation (avg/min/max/last über Fenster), `for`. Zustandsregeln (Unit fehlgeschlagen, Port nicht erreichbar). Ereignisregeln (Login-Fehler > N in M min, neue Checklisten-Abweichung). |
| **Zusammengesetzt** | AND/OR/NOT über Bedingungen, Zeitfenster-Bedingungen (z. B. nur Mo–Fr 08–18), **Abhängigkeiten/Unterdrückung** (wenn Basisregel feuert, werden abhängige Regeln unterdrückt). |
| **Dynamisch: Baseline-Abweichung** | Saisonale Baseline (Stunde der Woche, Fallback Stunde des Tages), **robust** (Median und MAD). Alarm bei `|x − baseline| > k·MAD` (k konfigurierbar, Standard 4) plus absolute Mindestabweichung gegen Rauschen. **Lernphase:** Regel inaktiv bis mindestens 7 Tage Daten vorliegen (UI zeigt Fortschritt). Alarmzeiträume werden aus der Baseline-Berechnung ausgeschlossen. |
| **Dynamisch: Trendvorhersage** | Robuste lineare Regression (z. B. Theil–Sen) über wählbares Fenster (24 h/7 d). Prognostiziert die **Zeit bis zum Schwellwert** (z. B. Datenträger voll) und alarmiert, wenn sie unter T liegt (Standard: warning < 7 Tage, critical < 48 h) und die Prognosegüte ausreicht. |
| **Dynamisch: Änderungsrate** | Anstieg/Abfall pro Zeiteinheit über Grenzwert. |

**Qualität (MUSS):** Zustandsautomat **OK → Pending → Firing → Resolved** mit Hysterese und Flapping-Schutz; Deduplizierung per Fingerprint; Gruppierung (30 s Sammelzeit); Wiederholung (Standard 4 h); **Eskalation** (nach X min ohne Bestätigung zusätzlicher Kanal/höherer Schweregrad); **Bestätigen (Ack)** mit Kommentar; **Silences/Wartungsfenster** (einmalig und wiederkehrend, auditiert); **Backtest** („hätte diese Regel in den letzten 7 Tagen gefeuert?“); Testalarm; Alarmzustand überlebt Neustarts.

**Standard-Regelset (optional beim Setup aktivierbar):** Datenträger > 85 %/95 %, Datenträger-Trend < 7 Tage, RAM verfügbar < 10 %, Load > 2 × Kerne über 10 min, Dienst fehlgeschlagen, Neustart erforderlich > 7 Tage, Sicherheitsupdates > 0 seit > 3 Tagen, Zertifikat < 21 Tage, Anmeldefehler-Burst, Checklisten-Regression, Daemonica-Eigenzustand.

**Import/Export** der Regeln (YAML/JSON, validiert, versioniert).

### 8.4 Benachrichtigungskanäle (M2.4)

**Webhook (MUSS):**
- Ziel-URL **nur HTTPS** (HTTP nur per ausdrücklicher Freigabe für lokale Ziele), POST, konfigurierbare Header (Secrets verschlüsselt), JSON-Payload mit **versioniertem Schema**; Vorlagen (Go `text/template` mit Feld-Allowlist, kein Zugriff auf Funktionen mit Seiteneffekten); Presets: generisches JSON und Slack-kompatibel.
- Signatur `X-Daemonica-Signature: sha256=HMAC(secret, timestamp.body)` plus Zeitstempel (Replay-Schutz); Timeout 10 s; Wiederholungen mit Exponential-Backoff (5 Versuche), danach „Dead-Letter“-Anzeige; **keine Redirects**; **SSRF-Filter** wie in §8.2; TLS-Prüfung immer an (eigene CA optional).

**Mail (MUSS):** SMTP mit **erzwungenem TLS** (STARTTLS oder implizit), Zertifikatsprüfung, Authentifizierung nur über TLS, Absender/Empfängerlisten, Vorlagen (de/en; Text + HTML ohne externe Ressourcen), Stundenlimit, Testmail, Schutz vor Header-Injection, Zugangsdaten verschlüsselt.

**API (MUSS):** Lesende REST-API für externe Systeme: `GET /api/v1/alerts?state=…`, `/alerts/{id}`, `/rules`, `/metrics/query`, `/checklist/results`, `/health`. Prometheus-Exposition KANN.
- **API-Tokens:** 256 Bit, nur Hash gespeichert, einmalige Anzeige, **Scopes** (`alerts:read`, `metrics:read`, `checklist:read`; optionale Schreib-Scopes `alerts:ack`, `alerts:silence`), **Pflicht-Ablaufdatum** (max. 365 Tage), optionale IP-Beschränkung je Token, Rate-Limit, Widerruf, „zuletzt benutzt“. Erstellen/Widerrufen nur Admin + Step-up.
- API-Tokens sind die **einzigen Nicht-Passkey-Credentials** und dürfen **ausschließlich** diese Scopes bedienen (nie Admin-Aktionen, Dateien, Terminal, Benutzer). Die Netz-Allowlist gilt auch für die API.

**Routing und Meta-Überwachung (MUSS):** Regeln → Kanäle nach Schweregrad/Labels, Fallback-Kanal; **UI-Alarme immer aktiv**. Zustellprotokoll je Versuch; **fehlgeschlagene Zustellung wird prominent in der UI gezeigt** und löst einen Eigenalarm aus. Globales Ausgangs-Rate-Limit gegen Alarmfluten (Zusammenfassung statt Einzelversand).

### 8.5 Alarm-Center und Assistenten (M2.5)

- **Alarm-Center:** aktive/bestätigte/gelöste Alarme, Details (Verlauf, Graphausschnitt, Regel, Zustellungen), Ack, Silence, Filter; Zähler/Glocke in der Kopfzeile.
- **Regel-Assistent** („Wann soll ich dich alarmieren?“) in einfacher Sprache mit Live-Vorschau und Backtest; Kanal-Assistent mit Testversand; Aktivierung des Standard-Regelsets.

### 8.6 Rollen in Phase 2

Alarme und Checklisten-Ergebnisse sehen alle Rollen; Ack/Silence: Operator + Admin; Checkliste ausführen: Operator + Admin; Behebung, Regeln, Kanäle, API-Tokens: nur Admin (Kanäle/Tokens/Behebung mit Step-up). Details in Anhang A.

### 8.7 Abnahmekriterien Phase 2

- Test: Datei füllen, bis Datenträger > 90 % → Webhook-Testserver erhält Alarm innerhalb von 2 Intervallen, korrekt signiert; Auflösung nach Aufräumen.
- Trend-Regel feuert bei synthetischen Daten; Baseline-Regel bleibt in der Lernphase inaktiv und feuert danach bei Ausreißern.
- Mailversand gegen lokalen SMTP-Testserver mit TLS; Klartext-SMTP wird abgelehnt.
- API-Token mit falschem Scope wird abgewiesen; abgelaufene Token werden abgewiesen.
- SSRF-Tests (Loopback, `169.254.169.254`, DNS-Rebinding, Redirect) werden abgewiesen.
- Checkliste: Behebung + Rückgängig funktionieren; Neustart der VM erhält Alarmzustände und Regeln.

---

## 9. Phase 3 — Geführte Anwendungsverwaltung

**Voraussetzung:** Phase 2 ausdrücklich abgenommen (S1).

### 9.0 Meilensteine

| ID | Inhalt |
|---|---|
| M3.0 | Anwendungs-Framework, signierter App-Katalog, **Betriebsarten-Abstraktion (nativ/Docker)**, **Firewall-Automatik**, Erweiterung der ACME-Komponente, Backup-Framework |
| M3.1 | Docker |
| M3.2 | nginx (nativ und Docker; inkl. Zertifikatsverwaltung) |
| M3.3 | FreeRADIUS (nativ und Docker; unabhängig, kann parallel erfolgen) |
| M3.4 | Nextcloud (Docker und nativ) |
| M3.5 | Matrix (Synapse; Docker und nativ) |
| M3.6 | Integration (Backups, Alarme, Checkliste), Audit Phase 3, Abnahmepaket (**STOPP S1**) |

Reihenfolge: M3.0 → M3.1 → M3.2 → (M3.4, M3.5); M3.3 jederzeit nach M3.0. **Jede Anwendung wird in beiden Betriebsarten umgesetzt**; die Docker-Betriebsart setzt M3.1 voraus.

### 9.1 Anwendungs-Framework (M3.0)

**Modul-Schnittstelle (MUSS):** `Detect`, `Preflight`, `Plan`, `Install`, `Configure`, `Status/Health`, `Update`, `Backup`, `Restore`, `Uninstall`, `Logs`. Zustand in der Helper-DB (App, Version, Nicht-Geheim-Konfiguration, Pfade, Status); Geheimnisse im verschlüsselten Secret-Store.

**Geführte Installation (MUSS):** Wizard mit **Preflight** (freie Ports, RAM/Disk-Minimum, DNS der Domain zeigt auf den Server, Konflikte mit vorhandenen Diensten, Docker/nginx vorhanden), Plan-Vorschau, Live-Fortschritt, **Idempotenz und Wiederaufnahme** nach Abbruch, **transaktionaler Rollback** bei Fehlern. Die Seite „Anwendungen“ zeigt je App Status, Version, URL, Betriebsart, Aktionen.

**Wizard-Ablauf (MUSS):** (1) **Betriebsart** wählen, (2) Preflight, (3) Parameter (Domain, Zugangsdaten, Limits), (4) **Zugriff und Firewall**, (5) Plan-Vorschau, (6) Installation mit Live-Fortschritt, (7) Abschlussprüfung mit Funktionstest und Zusammenfassung (URLs, einmalig angezeigte Zugangsdaten, nächste Schritte).

**Betriebsarten (D-17, MUSS):**
- Jede Anwendung (nginx, FreeRADIUS, Nextcloud, Matrix) ist **nativ auf dem Server** oder **in Docker** installierbar. Der Wizard schlägt die empfohlene Betriebsart vor — **Nextcloud und Matrix: Docker; nginx und FreeRADIUS: nativ** — und bietet die Alternative gleichberechtigt an, mit verständlichem Vergleich (Isolation, Updates, Ressourcenbedarf, Backup, Auswirkungen auf die Firewall).
- Das Modul-Interface erhält `Modes()` (unterstützte Betriebsarten) sowie je Betriebsart eine eigene Implementierung von `Preflight/Install/Configure/Update/Backup/Restore/Uninstall`. `Status/Health/Logs` liefern in beiden Modi dasselbe Datenmodell, sodass UI, Alarme und Checkliste nicht unterscheiden müssen.
- Die Docker-Betriebsart setzt das Docker-Modul (M3.1) voraus; der Wizard bietet dessen Installation an. Die native Betriebsart nutzt apt-Pakete bzw. geprüfte Archive.
- Die Betriebsart ist nach der Installation **fest**. Ein Wechsel erfolgt per Backup → Deinstallation → Neuinstallation → Restore (Backups sind dafür betriebsartneutral, siehe unten); ein Migrationsassistent ist KANN.
- **Offizielle Quellen (D-19, MUSS):** Drittquellen (z. B. Docker, Matrix, optional nginx.org) werden ausschließlich von Anwendungsmodulen hinzugefügt und nur, wenn sie das **offizielle Repository des Herstellers/Projekts** sind. Pflicht je Quelle: im Katalog **gepinnter Schlüssel-Fingerprint**, `signed-by`-Keyring, eigene Quelldatei, nie über ein freies Eingabefeld. Die **offizielle Herkunft** (Link auf die Hersteller-Dokumentation, Domain, Fingerprint) wird bei der Umsetzung **recherchiert, nicht aus dem Gedächtnis angenommen**, im Katalog belegt und in `docs/DECISIONS.md` dokumentiert. Dasselbe gilt für Archive (Download-URL der Hersteller-Seite, Signatur/Prüfsumme) und Container-Images (offizielle Registry/Publisher-Namespace des Projekts, per Digest). Bei der Deinstallation kann die Quelle optional wieder entfernt werden.
- Es kann immer nur **eine** nginx-Instanz (nativ oder Docker) die Ports 80/443 belegen (Preflight).

**Kombinationsmatrix (der Preflight erzwingt sie):**

| Proxy ↓ / Anwendung → | Docker-App | native App |
|---|---|---|
| nginx **nativ** | ✔ über `127.0.0.1:<Port>` | ✔ über Unix-Socket bzw. `127.0.0.1` |
| nginx **Docker** | ✔ im internen Docker-Netz, App-Ports nicht auf dem Host veröffentlicht | ⚠ nur über die Bridge-Gateway-Adresse (Dienst bindet ausschließlich dort, plus Firewall-Regel); native Nextcloud wird mit nginx in Docker **nicht** unterstützt (PHP-FPM-Socket). Ist keine sichere Anbindung möglich, blockiert der Preflight mit Erklärung. |

**Firewall-Automatik (D-17, MUSS):**
- Im Wizard-Schritt „Zugriff und Firewall“ legt der Admin fest, **wer zugreifen darf** (nur die Dashboard-Allowlist-Netze / bestimmte Netze / öffentlich). Der Katalog definiert je App und Betriebsart die **benötigten Freigaben** (Protokoll, Port, Zweck, Standardquelle), z. B.: nginx TCP 443 (TCP 80 nur für HTTP-01 bzw. Redirect), Matrix-Föderation TCP 8448 nur wenn aktiviert und nicht über 443 delegiert, FreeRADIUS UDP 1812/1813 **nur von den NAS-Client-IPs**, Nextcloud und Matrix selbst keine eigene Freigabe (sie laufen hinter nginx).
- **Option „Benötigte Firewall-Regeln automatisch anlegen“:** Standard vorausgewählt; die Quelle ist standardmäßig auf die gewählten bzw. Allowlist-Netze beschränkt, „öffentlich“ nur nach ausdrücklicher Bestätigung. Der **Plan** zeigt die genauen Regeln vorab; die Anwendung läuft über Plan → Apply → Confirm mit Aussperr-Schutz (Phase 1) und Step-up.
- **Option abgewählt:** Die UI listet die fehlenden Freigaben als Anleitung; der App-Status zeigt „Firewall blockiert Port …“, sobald die Anwendung nicht erreichbar ist, mit Button „Regeln jetzt anlegen“.
- Backend `ufw`; ist es nicht installiert oder aktiv, bietet der Wizard die Einrichtung an (M1.5b). Bei anderen Backends (z. B. `firewalld`) zeigt Daemonica die benötigten Regeln nur als Anleitung.
- **Kennzeichnung und Pflege:** Alle automatisch angelegten Regeln tragen den Kommentar `daemonica:<app>:<zweck>`. Daemonica gleicht sie bei Konfigurationsänderungen ab (z. B. Föderation an/aus, NAS-Client hinzugefügt/entfernt), erkennt Abweichungen („Regeln fehlen/zusätzlich“) und entfernt sie bei der Deinstallation nach Bestätigung.
- **Docker:** Veröffentlichte Container-Ports umgehen `ufw`-Eingangsregeln. Für Docker-Betriebsarten stellt Daemonica die Regeln so her, dass sie **tatsächlich greifen** (Lösung aus M3.1, z. B. `DOCKER-USER`/ufw-route-Regeln), und **verifiziert die Wirksamkeit** per Regelwerk-Analyse und, soweit lokal möglich, per Verbindungstest.

**App-Katalog (MUSS):** Ein **im Paket enthaltener, signierter Katalog** (`catalog.json`) definiert pro App **und Betriebsart**: bei Docker Images **per Digest** und Compose-Vorlagen; bei nativ Pakete/Quellen mit gepinntem Schlüssel-Fingerprint bzw. Archiv-Quelle mit Prüfsumme/Signatur; außerdem Mindestversionen, Release-Hinweise, die **benötigten Firewall-Freigaben** und für jeden Eintrag den **Beleg der offiziellen Herkunft** (D-19). App-Updates erfolgen über den Katalog (neues Daemonica-Release). Ein Online-Abgleich ist KANN und wird als „nicht verifiziert“ gekennzeichnet.

**Backup/Restore (MUSS):** je App Daten + Datenbank-Dump (SOLL in einem **betriebsartneutralen Format**, damit eine Wiederherstellung auch in der anderen Betriebsart möglich ist); Ziel standardmäßig `/var/backups/daemonica/<app>/` (`0700`), Aufbewahrung (Standard 7 täglich/4 wöchentlich), Zeitplan über das Jobs-Modul aus Phase 1; geführte Wiederherstellung; Hinweis auf Test-Restore. Verschlüsselung der Sicherungen (z. B. `age`) SOLL.

**Integration:** Jede App liefert Health-Metriken und Standardregeln an Phase 2 (Container down, Zertifikat läuft ab, Backup fehlgeschlagen/veraltet, Update verfügbar) und zusätzliche Prüfungen für die Checkliste.

### 9.2 Docker (M3.1)

- **Installation:** Standard **offizielles Docker-APT-Repository** (`docker-ce`, `docker-ce-cli`, `containerd.io`, Buildx- und Compose-Plugin) mit **gepinntem Schlüssel-Fingerprint**; du MUSST den Fingerprint vor dem Eintragen aus der offiziellen Docker-Dokumentation recherchieren und in `docs/DECISIONS.md` belegen. Alternativ im Wizard wählbar: Distributionspakete (konservativ).
- **Daemon-Härtung** (`daemon.json`): `no-new-privileges`, `live-restore`, Log-Rotation (`local` bzw. `json-file` mit Limits), `userland-proxy: false`, `icc: false` für das Standardnetz. `userns-remap` optional unter „Erweitert“ (Warnung zu Volume-Rechten).
- **Port-Regel:** Container-Ports werden **nur an `127.0.0.1`** gebunden. Veröffentlichung auf `0.0.0.0` nur nach ausdrücklicher Admin-Entscheidung mit Warnung; die Checkliste meldet solche Fälle. **Ausnahmen** sind Container, deren Zweck der direkte Netzzugriff ist (nginx 80/443 und FreeRADIUS UDP 1812/1813 in der Docker-Betriebsart): Sie werden nur an die im Wizard gewählten Adressen gebunden und zugleich per Firewall-Regel auf die erlaubten Quellen beschränkt (Firewall-Automatik, §9.1). Hinweis in der UI: Docker umgeht `ufw` (iptables-Ketten); Daemonica legt dafür geeignete Schutzregeln (`DOCKER-USER`) an bzw. dokumentiert die gewählte Lösung in einer ADR.
- **Verwaltung (MUSS):** Container (Liste, Status, Start/Stop/Restart, Logs-Stream, Ressourcen, Inspect mit **maskierten** Env-/Secret-Werten), Images (Liste, Pull nur aus den im Katalog hinterlegten **offiziellen** Registries/Publishern und bei Katalog-Apps per Digest, Entfernen, Prune mit Vorschau), Volumes (Liste, Größe), Netzwerke (Liste), Compose-Projekte (von Daemonica verwaltete unter `/opt/daemonica/apps/<app>/`; fremde Projekte nur lesen). Shell im Container KANN (Admin + Step-up).
- **Zugriff:** Der Docker-Socket wird **nie** an Web-Prozess, Container oder Benutzer weitergegeben und kein Konto wird zur Gruppe `docker` hinzugefügt. Nur der Helper spricht die Docker Engine API (schmaler eigener HTTP-über-Unix-Client oder minimales SDK; Abhängigkeitslast in einer ADR abwägen) und nur mit einer Allowlist von Operationen. Es gibt **keine** Operation „starte beliebiges Image mit beliebigen Optionen“.
- **Container-Standards für alle Vorlagen (MUSS):** `cap_drop: [ALL]` (+ nur nötige `cap_add`), `security_opt: [no-new-privileges:true]`, `read_only: true` wo möglich (+ `tmpfs`), Nicht-root-`user:` wo unterstützt, Ressourcenlimits (Speicher/CPU/PIDs), Healthchecks, `restart: unless-stopped`, je App isoliertes Netz (nur der Frontend-Container im Proxy-Netz), Geheimnisse als Dateien (`0400`) bzw. Docker-Secrets statt Umgebungsvariablen, Images per Digest, **kein** `privileged`, **kein** Host-Netz/-PID, **keine** Docker-Socket-Mounts; Daten unter `/var/lib/daemonica/apps/<app>/`.

### 9.3 nginx (M3.2; nativ oder Docker, empfohlen nativ)

- **Rolle:** Reverse Proxy für die Anwendungen (Nextcloud, Matrix). Das Dashboard selbst bleibt hinter eigenem TLS und wird **nicht** über nginx ausgeliefert.
- **Installation:** Distributionspaket; das offizielle nginx.org-Repository des Herstellers KANN (nur mit gepinntem Schlüssel, D-19).
- **Wizard „Neue Website / neuer Proxy“:** Domain(s), Upstream (Container-Port auf `127.0.0.1` oder Unix-Socket), TLS über die **ACME-Komponente** (HTTP-01 per Webroot `/var/www/daemonica-acme` oder DNS-01), Vorlagen (generischer Reverse Proxy, Nextcloud, Matrix inkl. `/.well-known`), Frage „Wer soll zugreifen?“ (öffentlich oder nur bestimmte Netze → `allow/deny` + passende Firewall-Regel).
- **Sicherheitsprofil (MUSS):** TLS 1.2/1.3 mit aktueller Mozilla-Empfehlung (Profil „intermediate“, **zum Umsetzungszeitpunkt recherchieren und in einer ADR belegen**), OCSP-Stapling, `ssl_session_tickets off`, HSTS (Opt-in mit Erklärung), Sicherheits-Header, `server_tokens off`, `limit_req`/`limit_conn`-Zonen, pro Vorlage passende Body-Limits und Timeouts, HTTP→HTTPS-Redirect, **Default-Server** mit `return 444` und Dummy-Zertifikat für unbekannte Hostnamen.
- **Konfigurationsverwaltung:** von Daemonica verwaltete Dateien `/etc/nginx/conf.d/daemonica-<site>.conf` mit Marker-Header und Drift-Warnung bei manueller Änderung; **`nginx -t` vor jedem Reload**, atomar, Backup, automatisches Rollback bei Fehler. Fremde Konfigurationen sind nur lesbar (Dateimodul).
- **Zertifikate:** Liste mit Restlaufzeit, automatische Erneuerung per Timer (Jobs-Modul) mit Reload-Hook, Ablaufalarme (Phase 2).

**Docker-Betriebsart (MUSS wählbar):** nginx-Container (Image per Digest, `cap_drop: ALL` plus `NET_BIND_SERVICE`, `read_only`, Konfiguration und Zertifikate als **Read-only-Volumes**, von Daemonica generiert), veröffentlicht 80/443 nur an die gewählten Adressen. Er läuft im selben internen Docker-Netz wie die Docker-Anwendungen (deren Ports werden **nicht** auf dem Host veröffentlicht). Konfigurationsprüfung (`nginx -t`) im Container vor jedem Reload, Reload über eine Allowlist-Operation des Helpers, Rollback wie nativ. Zertifikate stellt die ACME-Komponente des Helpers aus und legt sie im Read-only-Volume ab. Native Anwendungen als Upstream: siehe Kombinationsmatrix (§9.1).

### 9.4 FreeRADIUS (M3.3; nativ oder Docker, empfohlen nativ)

**Wizard „RADIUS-Server einrichten“** für 802.1X (WLAN/LAN) und VPN-Authentifizierung:
- **Szenarien:** (1) Benutzername/Passwort per **PEAP-MSCHAPv2** oder **EAP-TTLS/PAP** (UI erklärt Sicherheitsunterschiede und die bekannten Schwächen von MSCHAPv2), (2) **EAP-TLS** mit Zertifikaten (SOLL: eigene Mini-CA erzeugen, Server-/Client-Zertifikate ausstellen, widerrufen, CRL), (3) PAP/CHAP für Appliances KANN.
- **Benutzer-Backend:** lokale SQL-Benutzerdatenbank (SQLite via `rlm_sql`); Benutzer anlegen/sperren/löschen/Passwort setzen, Gruppen, optionale VLAN-Attribute (KANN). Passwörter werden **nie angezeigt**; CSV-Import KANN; LDAP/AD-Anbindung KANN.
- **Clients (NAS):** Name, IP/CIDR, **Shared Secret** (generiert, ≥ 32 Zeichen, einmalig anzeigbar), Validierung.
- **Härtung (MUSS):** nur benötigte Module/Sites aktiv (`default`/`inner-tunnel` bereinigen), Status-Server aus, Bindung an konfigurierte Adressen, Betrieb als Benutzer `freerad`, korrekte Dateirechte, **keine Passwörter im Log** (`auth_badpass`/`auth_goodpass` aus), EAP-TLS ≥ 1.2, starke Zertifikate, Firewall-Vorschlag (UDP 1812/1813 nur von Client-IPs), Zertifikatsablaufalarm.
- **Werkzeuge:** Test (`radtest`/`radclient` gegen localhost über Helper), zeitlich begrenzter Debug-Modus mit Maskierung, Auth-Log (Accept/Reject mit Grund).
- **Konfigurationsverwaltung:** von Daemonica verwaltete Snippets, Pfade per Erkennung der installierten Version, Syntaxcheck (`freeradius -C`) vor Reload, Backup/Rollback.

**Docker-Betriebsart (MUSS wählbar):** offizielles FreeRADIUS-Image (laut Katalog, per Digest); Konfiguration, Zertifikate und SQLite-Datenbank als Volumes (Konfiguration schreibgeschützt eingebunden); UDP 1812/1813 nur an die gewählte Adresse gebunden und per Firewall-Automatik **auf die NAS-Client-IPs beschränkt** (bleibt synchron, wenn NAS-Clients geändert werden). Es gelten dieselben Härtungsanforderungen wie nativ (keine Passwörter im Log, nur benötigte Module, starke Zertifikate); der Syntaxcheck (`-C`) läuft im Container vor dem Neustart; Testwerkzeuge (`radtest`/`radclient`) werden über eine Allowlist-Operation im Container ausgeführt.

### 9.5 Nextcloud (M3.4; Docker oder nativ, empfohlen Docker)

- **Stack (Vorlage):** `nextcloud` (Apache-Variante) + PostgreSQL + Redis, gebunden an `127.0.0.1`, davor nginx (M3.2). Cron-Job über das Jobs-Modul.
- **Wizard:** Domain, Zertifikat/Proxy, Datenverzeichnis (Platz-Preflight), Upload-Limit (konsistent in nginx und PHP), Admin-Benutzer (generiertes Passwort einmalig anzeigen), `trusted_domains`, `overwriteprotocol=https`, `overwritehost`, `trusted_proxies`, Wartungsfenster, Telefonregion; sichere Teilen-/Registrierungs-Defaults; generierte DB-/Redis-Geheimnisse.
- **Verwaltung (MUSS):** Status/Version, Wartungsmodus, Anzeige der Ergebnisse der Nextcloud-Setup-/Sicherheitschecks, **Updates schrittweise** (keine Major-Sprünge; automatisches Vor-Backup, `occ upgrade`), Backup/Restore (Wartungsmodus → DB-Dump + Daten + Konfiguration → Modus aus), Logs. `occ` nur über eine **Allowlist** von Befehlen (kein freies `occ`).
- **Nicht enthalten:** Collabora/OnlyOffice, Talk-HPB, LDAP/SSO.

**Native Betriebsart (MUSS wählbar; setzt natives nginx voraus):** Installation aus dem offiziellen Nextcloud-Release-Archiv mit **Signatur- bzw. Prüfsummenverifikation** (Schlüssel-Fingerprint im Katalog gepinnt; bei der Umsetzung aus der offiziellen Dokumentation recherchieren und belegen); dedizierter Systembenutzer; **PHP-FPM-Pool** je Instanz (nur benötigte PHP-Module, Socket nur für nginx zugänglich); PostgreSQL und Redis nativ (Unix-Sockets, keine TCP-Bindung nach außen); Datenverzeichnis **außerhalb des Webroots**; nginx-Vorlage mit FastCGI; systemd-Härtung per Drop-ins, soweit mit Nextcloud verträglich (Scores dokumentieren). Updates schrittweise (keine Major-Sprünge) mit automatischem Vor-Backup nach dem Herstellerablauf; Pflege von PHP/Datenbank über apt (Kompatibilitätshinweis). Cron per Jobs-Modul (systemd-Timer). Verwaltung, Backup/Restore und `occ`-Allowlist verhalten sich wie in der Docker-Betriebsart.

### 9.6 Matrix (M3.5; Docker oder nativ, empfohlen Docker)

- **Stack (Vorlage):** Synapse + PostgreSQL hinter nginx; Element Web optional (KANN).
- **Wizard:** `server_name` (**Warnung: nachträglich nicht änderbar**), Host `matrix.<domain>`, Delegation über `/.well-known/matrix/{server,client}` (liegt die Hauptdomain nicht auf diesem Server, zeigt der Wizard die bereitzustellenden Dateien an), **Föderation Standard AUS** mit Erklärung der Folgen, **Registrierung Standard AUS**, Admin-Benutzer per Wizard (über Allowlist-Operation), Medien-Aufbewahrung, Rate-Limits, Presence aus; Hinweis zum **Sichern des Signing-Keys**.
- **nginx:** `/_synapse/admin` extern **blockiert**; Admin-API nur intern.
- **Verwaltung:** Status/Version, Benutzer anlegen/deaktivieren/Passwort-Reset (Allowlist-Operationen), Medien-Cleanup, Updates mit Vor-Backup und Hinweisen zu Datenbankmigrationen, Backup/Restore (DB + Medien + Signing-Key + Konfiguration), Logs. TURN/coturn ist nicht Teil von Phase 3 (Hinweis in der UI).

**Native Betriebsart (MUSS wählbar):** Synapse aus dem **offiziellen Matrix-APT-Repository** (Quelle und Schlüssel-Fingerprint im Katalog gepinnt, bei der Umsetzung recherchieren und belegen) oder aus dem Distributionspaket, sofern dessen Version die Mindestversion des Katalogs erfüllt; eigener Systembenutzer, PostgreSQL nativ (Unix-Socket), Listener nur an `127.0.0.1` bzw. Unix-Socket hinter nginx, systemd-Härtung per Drop-in, generierte und validierte Konfiguration, Updates über apt (Updates-Modul) mit Vor-Backup-Hinweis. Wizard-Optionen (Föderation, Registrierung, `.well-known`, Signing-Key-Hinweis), Verwaltung und Backup/Restore verhalten sich wie in der Docker-Betriebsart.

### 9.7 Abnahmekriterien Phase 3

Auf frischer VM: Docker-Installation mit Härtung; nginx-Site mit gültigem (Staging-)Zertifikat und `testssl`-Ergebnis ohne kritische Befunde; Nextcloud über Domain nutzbar, **Backup → Zerstören → Restore** erfolgreich; Matrix-Server mit Admin-Benutzer, Föderation aus, Admin-API extern nicht erreichbar; FreeRADIUS beantwortet `radtest` korrekt (Accept/Reject), Secrets nie im Log; Deinstallation je App entfernt Container/Konfigurationen sauber (Daten nur auf ausdrücklichen Wunsch); alle Container-Standards (§9.2) per `docker inspect` nachweisbar.

**Betriebsarten:** Jede der vier Anwendungen wird in der empfohlenen **und** in der alternativen Betriebsart installiert, funktional geprüft, gesichert/wiederhergestellt und deinstalliert; unzulässige Kombinationen (§9.1) werden vom Preflight mit Erklärung abgewiesen.

**Firewall-Automatik:** Mit aktivierter Option entstehen exakt die im Plan gezeigten Regeln (Kommentar `daemonica:<app>:<zweck>`); die Anwendung ist aus erlaubten Netzen erreichbar und aus nicht erlaubten nicht (Docker-Veröffentlichung eingeschlossen; Wirksamkeit belegt durch Regelwerk-Analyse und Verbindungstest). Ohne die Option zeigt die Anwendung die fehlenden Freigaben an und bietet „Regeln jetzt anlegen“. Die Deinstallation entfernt die Regeln nach Bestätigung; Änderungen wie Föderation an/aus oder neue NAS-Clients passen die Regeln an.

---

## 10. Annahmen des Spec-Autors (vom Auftraggeber zu bestätigen)

> Bereits bestätigt: **A-01** und **A-25 bis A-29**. Alle übrigen Annahmen gelten bis zur Bestätigung im Abnahmepaket Phase 1.

Diese Punkte wurden **nicht** ausdrücklich entschieden, sondern mit sicheren Standardwerten festgelegt. Sie gelten bis zur Bestätigung im Abnahmepaket Phase 1. Das ausführende KI-Modell setzt sie um und stellt sie im Abnahmepaket zur Bestätigung vor.

| ID | Annahme |
|---|---|
| A-01 | Projektname **Daemonica** (aus dem Logo); Binaries `daemonica-web`, `daemonica-helper`, `daemonica-admin`; Paketname `daemonica`. **(bestätigt)** |
| A-02 | Architekturen: amd64 und arm64. |
| A-03 | Standardport 8443; Ersteinrichtung nur über Loopback/SSH-Tunnel bzw. das beim Bootstrap angegebene Netz. |
| A-04 | Datenhaltung SQLite (`modernc.org/sqlite`, CGO-frei); zwei getrennte Datenbanken (Helper/Web) plus `metrics.db` in Phase 2. |
| A-05 | UI-Bibliotheken: Tailwind + Radix, Inter/JetBrains Mono (selbst gehostet), CodeMirror 6, xterm.js, uPlot. |
| A-06 | Sitzungen: Idle 30 min, absolut 12 h, Step-up 5 min (konfigurierbar nur innerhalb von Grenzen). |
| A-07 | Zwei Passkeys werden dringend empfohlen (dauerhafter Hinweis), aber nicht erzwungen; der letzte Passkey ist nicht löschbar. |
| A-08 | Erhöhter Terminalmodus nur für Admin, max. 30 min; Standard-Shell mit `no_new_privs`. |
| A-09 | Rollenmatrix gemäß Anhang A (Nur-Lesen ohne Logs, Dateien, Terminal). |
| A-10 | Terminal-Eingaben werden nicht aufgezeichnet; Audit-Log wird vom Helper geführt (Hash-Kette). |
| A-11 | `sshd`-Konfiguration ist in Phase 1 nur lesbar; Änderungen erst über die Phase-2-Checkliste. |
| A-12 | Firewall-Verwaltung über `ufw`; andere Backends nur lesend. |
| A-13 | Verwaltete Jobs als systemd-Timer; Cron wird angezeigt und (SOLL) bearbeitbar. |
| A-14 | ACME: DNS-01 geführt/manuell (Provider-Plugins KANN), HTTP-01/TLS-ALPN-01 nur bei freien Ports; Tests gegen Let’s-Encrypt-Staging. |
| A-15 | Docker: offizielles Docker-Repository als Standard, Distributionspakete als Option. |
| A-16 | Matrix: Synapse; Föderation und Registrierung standardmäßig AUS. |
| A-17 | Nextcloud: Apache-Image + PostgreSQL + Redis; ohne Collabora/Talk. |
| A-18 | FreeRADIUS: lokale SQLite-Benutzerdatenbank, PEAP-MSCHAPv2/EAP-TTLS, EAP-TLS (SOLL); LDAP/AD KANN. |
| A-19 | App-Katalog signiert im Paket, Images per Digest; Updates über Daemonica-Releases. |
| A-20 | Keine Lizenz festgelegt: `LICENSE` enthält nur einen Platzhalter („All rights reserved – Lizenz noch festzulegen“). |
| A-21 | Kein Self-Update; Updates ausschließlich über apt. |
| A-22 | Aufbewahrung der Metriken: 48 h roh / 30 d (1 min) / 400 d (15 min), Limit 1 GiB. |
| A-23 | Checklisten-Referenzen (CIS/BSI) nur als Verweis, eigene Formulierungen. |
| A-24 | Repository-Hosting und CI sind nicht vorgegeben: lokales Git-Repo, lokale `make`-Ziele; Commits in Englisch (Conventional Commits). |
| A-25 | Paketmitschnitt: `tcpdump` nur zur Erfassung, eigener Go-Parser für die Live-Ansicht; Standardwerte 5 min / 100.000 Pakete / 100 MiB / Snaplen 96 Byte / Aufbewahrung 24 h / Gesamtlimit 1 GiB; ausschließlich Admin mit Step-up bei jedem Start; Dashboard-Port standardmäßig ausgeschlossen. **(bestätigt)** |
| A-26 | „Logs“ aus der Phase-1-Erweiterung wurde als **Firewall-Logs** interpretiert (die allgemeine journald-Logansicht bestand bereits). Firewall-Logs: Operator ✔, Nur-Lesen ✖; keine externen Lookups (GeoIP/Reverse-DNS). **(bestätigt)** |
| A-27 | Die Betriebsart einer Anwendung ist nach der Installation fest; ein Wechsel erfolgt über Backup → Neuinstallation → Restore (betriebsartneutrales Backup SOLL, Migrationsassistent KANN). **(bestätigt)** |
| A-28 | Firewall-Automatik: Option im Wizard standardmäßig **vorausgewählt**, Quelle standardmäßig auf Allowlist-/gewählte Netze beschränkt, „öffentlich“ nur mit ausdrücklicher Bestätigung; Regeln mit Kommentar `daemonica:<app>:<zweck>`; Backend `ufw`, bei anderen Backends nur Anleitung. **(bestätigt)** |
| A-29 | Native Betriebsart: Nextcloud aus dem offiziellen Release-Archiv (Signaturprüfung) mit PHP-FPM, PostgreSQL, Redis und nativem nginx; Synapse aus dem offiziellen Matrix-APT-Repository oder einem ausreichend aktuellen Distributionspaket. Drittquellen nur über den Katalog mit gepinntem Schlüssel-Fingerprint. nginx in Docker mit nativer Nextcloud wird nicht unterstützt. **(bestätigt)** |

---

## Anhang A — Rollenmatrix

Legende: ✔ erlaubt · ✖ nicht erlaubt · **(S)** erfordert Step-up · „eigene“ = nur Objekte des zugeordneten Linux-Benutzers. Die Matrix ist die **Quelle** für Policy-Tabelle und generierte Autorisierungstests.

| Funktion | Admin | Operator | Nur-Lesen |
|---|---|---|---|
| Systemübersicht, Dienste-Liste, Netzwerk-/Firewall-/Update-/Datenträger-Ansicht (lesen) | ✔ | ✔ | ✔ |
| Dienste start/stop/restart/reload | ✔ (geschützte Units **(S)**) | ✔ (außer geschützte Units) | ✖ |
| Dienste enable/disable/mask | ✔ **(S)** | ✖ | ✖ |
| Logs (journald) | ✔ | ✔ | ✖ |
| Prozesse anzeigen | ✔ | ✔ | ✔ |
| Prozesssignale | ✔ (alle, außer geschützte) | eigene | ✖ |
| Linux-Benutzer/Gruppen anzeigen | ✔ | ✔ | ✔ |
| Linux-Benutzer/Gruppen ändern, sudo-Mitgliedschaft | ✔ **(S)** | ✖ | ✖ |
| SSH-Schlüssel verwalten | ✔ alle **(S)** bei fremden | eigene | ✖ |
| Netzwerk ändern | ✔ **(S)** | ✖ | ✖ |
| Firewall ändern | ✔ **(S)** | ✖ | ✖ |
| Firewall-Logs ansehen | ✔ | ✔ | ✖ |
| Paketmitschnitt starten/stoppen | ✔ **(S, je Start)** | ✖ | ✖ |
| Mitschnitte ansehen, herunterladen, löschen | ✔ (**S** für Download) | ✖ | ✖ |
| Updates installieren, Pakete (de)installieren | ✔ **(S)** | ✖ | ✖ |
| Datenträger mount/unmount/fstab | ✔ **(S)** | ✖ | ✖ |
| Zeitzone/Hostname ändern | ✔ **(S)** | ✖ | ✖ |
| Neustart/Herunterfahren | ✔ **(S)** | ✖ | ✖ |
| Jobs ansehen | ✔ | ✔ | ✔ |
| Jobs ausführen, aktivieren/deaktivieren | ✔ | ✔ | ✖ |
| Jobs anlegen/ändern/löschen | ✔ (root-Jobs **(S)**) | ✖ | ✖ |
| Dateimanager (im Rahmen der Linux-Rechte) | ✔ | ✔ | ✖ |
| Dateimanager „als root“ | ✔ **(S)** | ✖ | ✖ |
| Terminal Standard-Shell | ✔ | ✔ | ✖ |
| Terminal erhöht (root/sudo) | ✔ **(S, je Öffnen)** | ✖ | ✖ |
| Dashboard-Konten/Rollen verwalten | ✔ **(S)** | ✖ | ✖ |
| Eigene Passkeys/Sitzungen verwalten | ✔ (**S** für Passkey hinzufügen/entfernen) | ✔ (**S**) | ✔ (**S**) |
| Audit-Log ansehen/exportieren | ✔ | ✖ | ✖ |
| Dashboard-Einstellungen (TLS, Allowlist, Sitzungszeiten, Limits) | ✔ **(S)** | ✖ | ✖ |
| *Phase 2:* Alarme/Checkliste ansehen | ✔ | ✔ | ✔ |
| *Phase 2:* Check ausführen; Ack/Silence | ✔ | ✔ | ✖ |
| *Phase 2:* Checklisten-Behebung | ✔ **(S)** | ✖ | ✖ |
| *Phase 2:* Regeln verwalten | ✔ | ✖ | ✖ |
| *Phase 2:* Kanäle und API-Tokens verwalten | ✔ **(S)** | ✖ | ✖ |
| *Phase 3:* Anwendungen ansehen | ✔ | ✔ | ✔ |
| *Phase 3:* Anwendungen installieren/ändern/aktualisieren/deinstallieren, Docker-/nginx-/RADIUS-Verwaltung | ✔ **(S)** | ✖ | ✖ |
| *Phase 3:* Von Anwendungen verwaltete Firewall-Regeln anlegen/anpassen/entfernen (auch automatisch im Wizard) | ✔ **(S)** | ✖ | ✖ |
| *Phase 3:* Container-Logs ansehen, App-Backup ausführen | ✔ | ✔ | ✖ |

## Anhang B — Aktionen mit Step-up (Kurzfassung)

Alle mit **(S)** markierten Aktionen aus Anhang A. Zusätzlich immer: Passkey hinzufügen/entfernen, Rollen-/Konto-Änderungen, API-Token erstellen/widerrufen, TLS-/Allowlist-Änderungen, erhöhter Terminalmodus, „Als root“-Dateimodus, Zugriff auf sensible Pfade, Paketmitschnitt starten und herunterladen, Checklisten-Behebung mit Risiko ≥ mittel, Löschen von Daten mit „Name eintippen“.

## Anhang C — Audit-Ereignisschema (JSON Lines)

```json
{
  "ts": "2026-10-24T12:00:00.123Z",
  "event_id": "01J…ULID",
  "actor": {"account_id": "…", "name": "…", "role": "admin", "linux_user": "…"},
  "source_ip": "203.0.113.5",
  "session": "sha256:…(gekürzt)",
  "action": "users.create",
  "target": "linux_user:alice",
  "params": {"shell": "/bin/bash", "groups": ["dev"]},
  "step_up": true,
  "result": "ok|denied|error",
  "reason": "optional, ohne sensible Daten",
  "prev_hash": "sha256:…",
  "hash": "sha256:…"
}
```
`params` enthalten **nie** Passwörter, Tokens, Dateiinhalte oder Terminal-Eingaben (Felder werden per Allowlist je Aktion befüllt).

## Anhang D — Helper-Operationen (Auszug, Namensraum; vollständige Liste in `docs/ARCHITECTURE.md`)

`auth.*` (Zeremonien, Grants, Step-up), `accounts.*`, `audit.append|verify`, `sysinfo.*`, `systemd.list|get|start|stop|restart|reload|enable|disable|mask`, `journal.query|follow`, `proc.list|signal`, `users.*`, `groups.*`, `sshkeys.*`, `fs.list|stat|read|write|mkdir|rename|copy|move|delete|chmod|chown|upload|download`, `pty.open|resize|close`, `net.get|plan|apply|confirm|rollback`, `firewall.status|rules|plan|apply|confirm|logs.query|logs.follow`, `capture.start|stop|list|download|delete`, `jobs.*`, `apt.*`, `disks.*`, `mounts.*`, `fstab.*`, `time.*`, `host.*`, `power.*`, `tls.*`, `acme.*`, `config.*`; Phase 2: `check.run|plan|apply|undo`, `notify.*`; Phase 3: `docker.*`, `nginx.*`, `radius.*`, `apps.*`.
Jede Operation hat: Name, Eingabeschema (strikt), erforderliche Rolle/Step-up, Audit-Felder, Timeout, Ausgabelimit, Rollback-Verhalten.

## Anhang E — Änderungsverlauf

| Version | Änderungen |
|---|---|
| 1.0 | Erstfassung (Phasen 1–3, Sicherheitsarchitektur, Design, Arbeitsweise). |
| 1.1 | **Phase 1:** Firewall erweitert um Status (mit Ampel), Regelwerk (Klartext-Erklärung, Rohansicht), Firewall-Logs und Paketmitschnitt (M1.5a–d; neue Audit-Prüfung SA-15, Rollen, Annahmen A-25/A-26). **Phase 3:** Betriebsart (nativ/Docker) je Anwendung wählbar mit Kombinationsmatrix und nativen Varianten für nginx, FreeRADIUS, Nextcloud, Matrix; optionale automatische Firewall-Freigaben (Firewall-Automatik); neue Annahmen A-27 bis A-29. |
| 1.2 | **Neue verbindliche Entscheidung D-19:** ausschließlich offizielle Quellen für Repositories, Archive und Images (Herkunft recherchiert, im Katalog belegt, SA-13 erweitert). Annahmen A-25 bis A-29 vom Auftraggeber bestätigt. |
| 1.3 | **Projektname korrigiert:** „Daemonia“ → **„Daemonica“** (wie im Logo) in allen Bezeichnern, Pfaden, Paket-, Dienst- und Dateinamen; A-01 bestätigt. **Design:** Dunkles Theme ist Standard, unabhängig von `prefers-color-scheme` (§5.2). |

---

*Ende der Spezifikation. Bei Unklarheiten gilt §0.3: sichere Annahme treffen, in `docs/DECISIONS.md` protokollieren, weiterarbeiten — außer bei S1–S5.*
