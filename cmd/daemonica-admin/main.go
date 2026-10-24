// Command daemonica-admin is the root-only CLI for bootstrap, recovery and
// emergency operations. It talks to the helper over /run/daemonica/admin.sock
// (mode 0600 root) — the helper additionally verifies UID 0 via SO_PEERCRED.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
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
  tls-status                   Zertifikatsstatus anzeigen
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
		fmt.Fprintln(os.Stderr, "'tls-status' folgt mit der Zertifikatsverwaltung in den Einstellungen.")
		os.Exit(2)
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
		return fmt.Errorf("Kontoname fehlt: daemonica-admin recover <konto> [--revoke-all]")
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
