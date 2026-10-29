// Command daemonica-admin is the root-only CLI for bootstrap, recovery and
// emergency operations. It talks to the helper over /run/daemonica/admin.sock
// (mode 0600 root) — the helper additionally verifies UID 0 via SO_PEERCRED.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

const usage = `daemonica-admin – Notfall- und Einrichtungswerkzeug (nur root)

Befehle:
  bootstrap [--allow <CIDR>]   Einmal-Token für die Ersteinrichtung erzeugen (60 min gültig)
  status                       Zustand von Daemonica anzeigen
  allowlist-reset              Netz-Allowlist auf Loopback zurücksetzen (Notfall)
  audit-verify                 Hash-Kette des Audit-Logs prüfen
  recover <konto> [--revoke-all]  Wiederherstellung bei Passkey-Verlust
  list-accounts                Dashboard-Konten auflisten
  tls-status                   Zertifikat und laufende Ausstellung anzeigen
  tls-install <kette.pem> <schlüssel.pem>
                               eigenes Zertifikat installieren (z. B. wenn das alte
                               abgelaufen ist und der Browser keine Passkeys mehr zulässt)
  tls-issue [--method http-01|tls-alpn-01|dns-01] [--staging] --agree-tos
                               Let's-Encrypt-Zertifikat ausstellen (DNS-01: zeigt den
                               TXT-Eintrag und wartet auf Enter)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Fehler: daemonica-admin muss als root ausgeführt werden (sudo).")
		os.Exit(1)
	}
	sock := os.Getenv("DAEMONICA_ADMIN_SOCKET")
	if sock == "" {
		sock = "/run/daemonica/admin.sock"
	}
	c := &rpc.Client{Socket: sock, Timeout: 5 * time.Minute}
	ctx := context.Background()
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "bootstrap":
		err = bootstrap(ctx, c, args)
	case "status":
		err = status(ctx, c)
	case "allowlist-reset":
		var out []string
		if err = c.Call(ctx, "admin.allowlist_reset", "", "", nil, &out); err == nil {
			fmt.Printf("Allowlist zurückgesetzt auf: %s\nBitte 'systemctl restart daemonica-web' ausführen.\n", strings.Join(out, ", "))
		}
	case "audit-verify":
		var res audit.VerifyResult
		if err = c.Call(ctx, "admin.audit_verify", "", "", nil, &res); err == nil {
			if res.OK {
				fmt.Printf("Audit-Kette intakt: %d Einträge.\n", res.Records)
			} else {
				fmt.Printf("WARNUNG: Audit-Kette beschädigt in Zeile %d: %s\n", res.BadLine, res.Problem)
				os.Exit(3)
			}
		}
	case "recover":
		err = recoverAccount(ctx, c, args)
	case "list-accounts":
		var accs []helper.Account
		if err = c.Call(ctx, "admin.list_accounts", "", "", nil, &accs); err == nil {
			if len(accs) == 0 {
				fmt.Println("Keine Konten vorhanden (Einrichtung noch nicht abgeschlossen).")
			}
			for _, a := range accs {
				state := "aktiv"
				if a.Disabled {
					state = "deaktiviert"
				}
				fmt.Printf("%-24s %-9s linux=%-16s passkeys=%d  %s\n", a.Name, a.Role, a.LinuxUser, a.Passkeys, state)
			}
		}
	case "tls-status":
		err = tlsStatus(ctx, c)
	case "tls-install":
		err = tlsInstall(ctx, c, args)
	case "tls-issue":
		err = tlsIssue(ctx, c, args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		if code := rpc.ErrorCode(err); code == rpc.CodeUnavailable {
			fmt.Fprintln(os.Stderr, "Fehler: daemonica-helper ist nicht erreichbar. Läuft 'systemctl status daemonica-helper'?")
		} else {
			fmt.Fprintf(os.Stderr, "Fehler: %v\n", err)
		}
		os.Exit(1)
	}
}

func bootstrap(ctx context.Context, c *rpc.Client, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	var allow multi
	fs.Var(&allow, "allow", "zusätzliches erlaubtes Netz (CIDR), mehrfach möglich")
	_ = fs.Parse(args)

	if len(allow) == 0 {
		if s := suggestFromSSH(os.Getenv("SSH_CLIENT")); s != "" {
			fmt.Printf("Hinweis: Du bist per SSH aus %s verbunden.\n", s)
			fmt.Printf("  Um dieses Netz direkt freizugeben: sudo daemonica-admin bootstrap --allow %s\n\n", s)
		}
	}
	var res helper.BootstrapResult
	if err := c.Call(ctx, "admin.bootstrap", "", "", helper.BootstrapParams{Allow: allow}, &res); err != nil {
		return err
	}
	fmt.Printf(`Einrichtungs-Token (einmalig, gültig bis %s UTC):

    %s

So geht es weiter:
  1. Auf deinem Rechner einen SSH-Tunnel öffnen:
       ssh -L 8443:127.0.0.1:8443 <benutzer>@<server>
  2. Im Browser https://localhost:8443 öffnen (Zertifikatswarnung im
     Setup-Modus ist erwartet – das Zertifikat ist nur temporär).
  3. Token eingeben und dem Einrichtungsassistenten folgen.

Erlaubte Netze: %s
Das Token wird nur gehasht gespeichert und kann nicht erneut angezeigt werden.
`, res.ExpiresAt.Format("2006-01-02 15:04"), res.Token, strings.Join(res.Allowlist, ", "))
	return nil
}

func recoverAccount(ctx context.Context, c *rpc.Client, args []string) error {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	revokeAll := fs.Bool("revoke-all", false, "alle bisherigen Passkeys des Kontos entfernen")
	// Allow the account name before or after the flag.
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	if name == "" && fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	if name == "" {
		return errors.New("kein Kontoname: daemonica-admin recover <konto> [--revoke-all]")
	}
	var res struct {
		Token           string    `json:"token"`
		ExpiresAt       time.Time `json:"expires_at"`
		SessionsEnded   int       `json:"sessions_ended"`
		PasskeysRemoved int       `json:"passkeys_removed"`
	}
	if err := c.Call(ctx, "admin.recover", "", "", map[string]any{"account": name, "revoke_all": *revokeAll}, &res); err != nil {
		return err
	}
	fmt.Printf(`Wiederherstellung für Konto %q:
  Beendete Sitzungen:  %d
  Entfernte Passkeys:  %d

Wiederherstellungs-Token (einmalig, gültig bis %s UTC):

    %s

Öffne das Dashboard, wähle „Ich habe ein Wiederherstellungs-Token“ und registriere
einen neuen Passkey. Das Token kann nicht erneut angezeigt werden.
`, name, res.SessionsEnded, res.PasskeysRemoved, res.ExpiresAt.Format("2006-01-02 15:04"), res.Token)
	return nil
}

func status(ctx context.Context, c *rpc.Client) error {
	var st helper.StatusResult
	if err := c.Call(ctx, "admin.status", "", "", nil, &st); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(b))
	if st.PublicWarn {
		fmt.Println("WARNUNG: Die Allowlist gibt das Dashboard öffentlich frei.")
	}
	return nil
}

// suggestFromSSH derives the most restrictive sensible entry from SSH_CLIENT
// ("ip port port"): the exact IPv4 address (/32), or the /64 for IPv6 because
// privacy extensions rotate the interface identifier. See DEC-007.
func suggestFromSSH(env string) string {
	f := strings.Fields(env)
	if len(f) == 0 {
		return ""
	}
	a, err := netip.ParseAddr(f[0])
	if err != nil {
		return ""
	}
	a = a.Unmap()
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, _ := a.Prefix(bits)
	return p.String()
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func printCert(v helper.CertView) {
	fmt.Printf("Domain:  %s\n", v.Domain)
	if v.Cert == nil {
		fmt.Println("Zertifikat: keines installiert")
	} else {
		fmt.Printf("Zertifikat: %s, Aussteller %s\n", strings.Join(v.Cert.Names, ", "), v.Cert.Issuer)
		fmt.Printf("Gültig bis: %s UTC (noch %d Tage)\n", v.Cert.NotAfter.UTC().Format("2006-01-02 15:04"), v.Cert.DaysLeft)
		renew := "nein"
		if v.AutoRenew {
			renew = "ja"
		}
		fmt.Printf("Quelle: %s", v.Source)
		if v.Method != "" {
			fmt.Printf(", Verfahren %s", v.Method)
		}
		fmt.Printf(", automatische Erneuerung: %s\n", renew)
	}
	if i := v.Issuance; i != nil {
		fmt.Printf("Letzte Ausstellung: %s über %s (%s), Zustand %s", i.CA, i.Method, i.Started.UTC().Format("2006-01-02 15:04"), i.State)
		if i.Error != "" {
			fmt.Printf(": %s", i.Error)
		}
		fmt.Println()
	}
}

func tlsStatus(ctx context.Context, c *rpc.Client) error {
	var v helper.CertView
	if err := c.Call(ctx, "admin.cert_status", "", "", nil, &v); err != nil {
		return err
	}
	printCert(v)
	return nil
}

func tlsInstall(ctx context.Context, c *rpc.Client, args []string) error {
	if len(args) != 2 {
		return errors.New("falscher Aufruf: daemonica-admin tls-install <kette.pem> <schlüssel.pem>")
	}
	chain, err := os.ReadFile(args[0]) //nolint:gosec // root names the file on its own console
	if err != nil {
		return err
	}
	key, err := os.ReadFile(args[1]) //nolint:gosec // root names the file on its own console
	if err != nil {
		return err
	}
	var info helper.CertInfo
	if err := c.Call(ctx, "admin.cert_upload", "", "", map[string]string{"cert_pem": string(chain), "key_pem": string(key)}, &info); err != nil {
		return err
	}
	fmt.Printf("Zertifikat installiert, gültig bis %s UTC. Das Dashboard nutzt es sofort.\n", info.NotAfter.UTC().Format("2006-01-02 15:04"))
	return nil
}

func tlsIssue(ctx context.Context, c *rpc.Client, args []string) error {
	fs := flag.NewFlagSet("tls-issue", flag.ExitOnError)
	method := fs.String("method", "http-01", "http-01, tls-alpn-01 oder dns-01")
	staging := fs.Bool("staging", false, "Let's Encrypt Staging (Test-Zertifikat, Browser vertrauen ihm nicht)")
	tos := fs.Bool("agree-tos", false, "Nutzungsbedingungen von Let's Encrypt akzeptieren")
	_ = fs.Parse(args)
	if !*tos {
		return errors.New("--agree-tos fehlt (Nutzungsbedingungen von Let's Encrypt)")
	}
	ca := "production"
	if *staging {
		ca = "staging"
	}
	var i helper.Issuance
	if err := c.Call(ctx, "admin.cert_issue", "", "", map[string]any{"method": *method, "ca": ca, "agree_tos": true}, &i); err != nil {
		return err
	}
	// Ctrl-C cancels the issuance in the helper (and closes an ACME window).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	asked := false
	for {
		var v helper.CertView
		if err := c.Call(ctx, "admin.cert_status", "", "", nil, &v); err != nil {
			return err
		}
		it := v.Issuance
		switch {
		case it == nil:
			return errors.New("keine Ausstellung gefunden")
		case it.State == "done":
			printCert(v)
			return nil
		case it.State == "failed" || it.State == "canceled":
			if it.State == "canceled" {
				return errors.New("die Ausstellung wurde abgebrochen")
			}
			return fmt.Errorf("die Ausstellung ist fehlgeschlagen: %s", it.Error)
		case it.State == "dns_wait" && !asked && it.Record != nil:
			asked = true
			fmt.Printf("\nLege beim DNS-Anbieter diesen Eintrag an (TTL so kurz wie möglich):\n\n    %s  TXT  %q\n\nDanach Enter drücken (Strg+C bricht ab) ... ", it.Record.Name, it.Record.Value)
			line := make(chan struct{})
			go func() { _, _ = bufio.NewReader(os.Stdin).ReadString('\n'); close(line) }()
			select {
			case <-line:
			case <-sig:
				_ = c.Call(ctx, "admin.cert_cancel", "", "", nil, nil)
				return errors.New("abgebrochen")
			}
			if err := c.Call(ctx, "admin.cert_dns_confirm", "", "", nil, nil); err != nil {
				return err
			}
			fmt.Println("Prüfe die Nameserver ...")
		}
		select {
		case <-sig:
			_ = c.Call(ctx, "admin.cert_cancel", "", "", nil, nil)
			return errors.New("abgebrochen")
		case <-time.After(2 * time.Second):
		}
	}
}
