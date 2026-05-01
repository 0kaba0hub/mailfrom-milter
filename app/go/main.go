// mailfrom-milter — Postfix milter that enforces From-header / envelope-from domain alignment.
//
// Only emails sent over authenticated SMTP (SASL) are checked.
// Unauthenticated connections (inbound relay, MX delivery) are passed through
// without inspection.
//
// The attack vector this prevents:
//
//	An authenticated user sets MAIL FROM to their own domain (which passes SPF/DKIM
//	for that domain) but forges the From: header with a different domain. The DKIM
//	signer picks up the From: domain and signs with that domain's key, allowing the
//	sender to impersonate any domain hosted on the same mail server.
//
// Environment variables:
//
//	LISTEN_ADDR   — TCP address to listen on (default: 0.0.0.0:10031)
//	ACTION        — Action on mismatch: reject | discard | quarantine_header | dunno
//	                (default: reject)
//	LOG_LEVEL     — Set to "debug" for verbose per-message logging
package main

import (
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/emersion/go-milter"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const (
	actionReject           = "reject"
	actionDiscard          = "discard"
	actionQuarantineHeader = "quarantine_header"
	actionDunno            = "dunno"

	defaultListenAddr = "0.0.0.0:10031"
	defaultAction     = actionReject

	headerEnvelopeFrom = "X-MF-Envelope-From"
	headerQuarantine   = "X-MF-Quarantine"

	// MFA001 — Mail From Alignment mismatch.
	// The From: header domain does not match the authenticated envelope sender domain,
	// which would allow DKIM to sign with a domain the sender is not authorised to use.
	rejectMsg = "5.7.1 Header From domain does not match envelope sender domain. Reason: MFA001"
)

type config struct {
	listenAddr string
	action     string
}

func loadConfig() config {
	cfg := config{
		listenAddr: envOrDefault("LISTEN_ADDR", defaultListenAddr),
		action:     strings.ToLower(envOrDefault("ACTION", defaultAction)),
	}
	switch cfg.action {
	case actionReject, actionDiscard, actionQuarantineHeader, actionDunno:
		// valid
	default:
		slog.Warn("unknown ACTION value, falling back to reject", "value", cfg.action)
		cfg.action = actionReject
	}
	return cfg
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------

var debug bool

func debugf(msg string, args ...any) {
	if debug {
		slog.Debug(msg, args...)
	}
}

// ---------------------------------------------------------------------------
// Milter implementation
// ---------------------------------------------------------------------------

var cfg config

// milterSession holds per-connection state.
// go-milter calls NewMilter() once per connection; a single connection may
// carry multiple messages, so per-message fields are reset in reset().
type milterSession struct {
	// Per-connection
	clientAddr string

	// Per-message (reset at each MAIL FROM)
	envelopeFrom string // MAIL FROM value, angle brackets stripped
	authUser     string // SASL {auth_authen} macro — empty for unauthenticated
	fromHeader   string // value of the first From: header seen

	// outcome flags set in Headers(), consumed in Body()
	authenticated bool // true when authUser != ""
	aligned       bool // true when domains match (valid only if authenticated)
}

func (s *milterSession) reset() {
	s.envelopeFrom = ""
	s.authUser = ""
	s.fromHeader = ""
	s.authenticated = false
	s.aligned = false
}

func (s *milterSession) Connect(host string, family string, port uint16, addr net.IP, m *milter.Modifier) (milter.Response, error) {
	if addr != nil {
		s.clientAddr = addr.String()
	}
	debugf("connect", "host", host, "addr", s.clientAddr)
	return milter.RespContinue, nil
}

func (s *milterSession) Helo(name string, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *milterSession) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	s.reset()
	s.envelopeFrom = strings.Trim(from, "<> \t")
	s.authUser = m.Macros["{auth_authen}"]
	debugf("mail from",
		"envelope_from", s.envelopeFrom,
		"auth_user", s.authUser,
		"client_addr", s.clientAddr,
	)
	return milter.RespContinue, nil
}

func (s *milterSession) RcptTo(rcptTo string, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

// Header is called once per message header, in order.
// We capture the first From: header value here.
func (s *milterSession) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	if strings.EqualFold(name, "From") && s.fromHeader == "" {
		s.fromHeader = value
		debugf("captured From header", "value", value)
	}
	return milter.RespContinue, nil
}

// Headers is called after all message headers have been received.
// For authenticated sessions we perform the domain alignment check here.
// If a mismatch is found, we reject/discard immediately — before receiving
// the body — which avoids unnecessary data transfer for rejected messages.
// For dunno and quarantine_header we let the message continue to Body()
// where we can add headers.
func (s *milterSession) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	if s.authUser == "" {
		// Not authenticated — inbound delivery, skip all checks.
		debugf("skip: unauthenticated",
			"envelope_from", s.envelopeFrom,
			"client_addr", s.clientAddr,
		)
		return milter.RespContinue, nil
	}

	s.authenticated = true

	envDomain := extractDomain(s.envelopeFrom)
	fromDomain := extractDomainFromHeader(s.fromHeader)

	if envDomain == "" || fromDomain == "" {
		slog.Warn("cannot extract domain(s), accepting without check",
			"envelope_from", s.envelopeFrom,
			"from_header", s.fromHeader,
			"auth_user", s.authUser,
			"client_addr", s.clientAddr,
		)
		s.aligned = true
		return milter.RespContinue, nil
	}

	if strings.EqualFold(envDomain, fromDomain) {
		s.aligned = true
		debugf("domains align",
			"envelope_domain", envDomain,
			"from_domain", fromDomain,
			"auth_user", s.authUser,
			"client_addr", s.clientAddr,
		)
		return milter.RespContinue, nil
	}

	// --- Domain mismatch ---
	slog.Warn("domain mismatch detected",
		"envelope_domain", envDomain,
		"from_domain", fromDomain,
		"envelope_from", s.envelopeFrom,
		"from_header", s.fromHeader,
		"auth_user", s.authUser,
		"client_addr", s.clientAddr,
		"action", cfg.action,
	)

	switch cfg.action {
	case actionReject:
		return milter.RespReject, nil
	case actionDiscard:
		return milter.RespDiscard, nil
	default:
		// quarantine_header and dunno: continue to Body() to add headers / log.
		return milter.RespContinue, nil
	}
}

// Body is called at the end of the message (after all body chunks).
// Header modifications (AddHeader) must happen here.
func (s *milterSession) Body(m *milter.Modifier) (milter.Response, error) {
	if !s.authenticated {
		return milter.RespAccept, nil
	}

	envDomain := extractDomain(s.envelopeFrom)
	fromDomain := extractDomainFromHeader(s.fromHeader)

	// Add X-MF-Envelope-From for every authenticated message.
	if err := m.AddHeader(headerEnvelopeFrom, s.envelopeFrom); err != nil {
		slog.Error("failed to add "+headerEnvelopeFrom, "err", err)
	}

	if s.aligned {
		slog.Info("accepted",
			"action", "accept",
			"envelope_domain", envDomain,
			"from_domain", fromDomain,
			"auth_user", s.authUser,
			"client_addr", s.clientAddr,
		)
		return milter.RespAccept, nil
	}

	// Mismatch — we are here only for quarantine_header and dunno actions.
	switch cfg.action {
	case actionQuarantineHeader:
		if err := m.AddHeader(headerQuarantine, "yes"); err != nil {
			slog.Error("failed to add "+headerQuarantine, "err", err)
		}
		slog.Info("quarantined via header",
			"action", actionQuarantineHeader,
			"envelope_domain", envDomain,
			"from_domain", fromDomain,
			"auth_user", s.authUser,
			"client_addr", s.clientAddr,
		)
	case actionDunno:
		slog.Info("dunno: mismatch logged, message accepted",
			"action", actionDunno,
			"envelope_domain", envDomain,
			"from_domain", fromDomain,
			"auth_user", s.authUser,
			"client_addr", s.clientAddr,
		)
	}

	return milter.RespAccept, nil
}

// BodyChunk is called for each body chunk. We don't inspect the body.
func (s *milterSession) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *milterSession) Abort(m *milter.Modifier) error {
	debugf("abort", "envelope_from", s.envelopeFrom)
	s.reset()
	return nil
}

// ---------------------------------------------------------------------------
// Domain extraction helpers
// ---------------------------------------------------------------------------

// extractDomain returns the lowercase domain from "user@domain.com" or "<user@domain.com>".
func extractDomain(addr string) string {
	addr = strings.Trim(addr, "<> \t")
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}

// extractDomainFromHeader handles the common From: header formats:
//
//	"Display Name <user@domain.com>"
//	"<user@domain.com>"
//	"user@domain.com"
func extractDomainFromHeader(header string) string {
	header = strings.TrimSpace(header)
	start := strings.LastIndex(header, "<")
	end := strings.LastIndex(header, ">")
	if start >= 0 && end > start {
		return extractDomain(header[start+1 : end])
	}
	return extractDomain(header)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	debug = strings.ToLower(os.Getenv("LOG_LEVEL")) == "debug"
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg = loadConfig()

	slog.Info("starting mailfrom-milter",
		"listen", cfg.listenAddr,
		"action", cfg.action,
	)

	// Macros (including {auth_authen}) are sent by Postfix automatically via
	// SMFIC_MACRO before each relevant SMTP command. Postfix milter_mail_macros
	// must include {auth_authen} (it does by default).
	server := &milter.Server{
		NewMilter: func() milter.Milter {
			return &milterSession{}
		},
		Actions: milter.OptAddHeader,
	}

	ln, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		slog.Error("listen failed", "addr", cfg.listenAddr, "err", err)
		os.Exit(1)
	}
	defer ln.Close()

	go func() {
		if err := server.Serve(ln); err != nil {
			slog.Error("server stopped", "err", err)
			os.Exit(1)
		}
	}()

	slog.Info("milter ready", "addr", cfg.listenAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("shutting down")
	server.Close()
}
