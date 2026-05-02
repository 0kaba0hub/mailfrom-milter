// mailfrom-milter — Postfix milter that enforces From-header / envelope-from
// domain alignment for authenticated SMTP sessions.
//
// Environment variables:
//
//	LISTEN_ADDR   — TCP address to listen on (default: 0.0.0.0:10031)
//	MF_ACTION     — Action on mismatch: reject | discard | quarantine_header | accept
//	                (default: reject)
//	REJECT_CODE   — SMTP reply code for reject action: 421 (temp) or 550 (permanent)
//	                (default: 421)
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
	actionDunno            = "accept"

	defaultListenAddr = "0.0.0.0:10031"
	defaultAction     = actionReject

	headerEnvelopeFrom = "X-MF-Envelope-From"
	headerFrom         = "X-MF-From"
	headerQuarantine   = "X-MF-Quarantine"
)

type config struct {
	listenAddr string
	action     string
	rejectCode string
}

func loadConfig() config {
	cfg := config{
		listenAddr: envOrDefault("LISTEN_ADDR", defaultListenAddr),
		action:     strings.ToLower(envOrDefault("MF_ACTION", defaultAction)),
		rejectCode: envOrDefault("REJECT_CODE", "421"),
	}
	switch cfg.action {
	case actionReject, actionDiscard, actionQuarantineHeader, actionDunno:
	default:
		slog.Warn("unknown MF_ACTION value, falling back to reject", "value", cfg.action)
		cfg.action = actionReject
	}
	if len(cfg.rejectCode) != 3 || (cfg.rejectCode[0] != '4' && cfg.rejectCode[0] != '5') {
		slog.Warn("invalid REJECT_CODE, falling back to 421", "value", cfg.rejectCode)
		cfg.rejectCode = "421"
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

const (
	checkPass = "pass"
	checkFail = "fail"

)

// rejectWith builds a reject response using cfg.rejectCode.
// The enhanced status code class (4.x.x / 5.x.x) is derived from the first digit.
func rejectWith(mfCode string) milter.Response {
	class := string(cfg.rejectCode[0])
	msg := cfg.rejectCode + " " + class + ".7.1 Rejected due of violation of policy. Error code: " + mfCode
	return milter.NewResponseStr(byte(milter.ActReplyCode), msg)
}

type milterSession struct {
	// Per-connection
	clientAddr string

	// Per-message (reset on each MAIL FROM)
	envelopeFrom  string
	authUser      string
	fromHeader    string
	flagCheckAuth string // pass / fail — authUser domain vs envelopeFrom domain
	flagCheckData string // pass / fail — envelopeFrom domain vs From: header domain
}

func (s *milterSession) reset() {
	s.envelopeFrom = ""
	s.authUser = ""
	s.fromHeader = ""
	s.flagCheckAuth = ""
	s.flagCheckData = ""
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

	// No SASL auth — inbound delivery, not our concern.
	// Return Accept: milter stops processing this message entirely.
	if s.authUser == "" {
		debugf("unauthenticated, skipping", "envelope_from", s.envelopeFrom)
		return milter.RespAccept, nil
	}

	// Check A: authUser domain vs envelopeFrom domain.
	authDomain := extractDomain(s.authUser)
	envDomain := extractDomain(s.envelopeFrom)
	if strings.EqualFold(authDomain, envDomain) {
		s.flagCheckAuth = checkPass
	} else {
		s.flagCheckAuth = checkFail
	}

	debugf("mail from",
		"envelope_from", s.envelopeFrom,
		"auth_user", s.authUser,
		"flag_check_auth", s.flagCheckAuth,
	)

	if s.flagCheckAuth == checkFail {
		switch cfg.action {
		case actionReject:
			s.logResult(actionReject)
			return rejectWith("MFC010001"), nil
		case actionDiscard:
			s.logResult(actionDiscard)
			return milter.RespDiscard, nil
		}
	}

	return milter.RespContinue, nil
}

func (s *milterSession) RcptTo(rcptTo string, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

// Header captures the email address from the first From: header.
func (s *milterSession) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	if strings.EqualFold(name, "From") && s.fromHeader == "" {
		s.fromHeader = extractEmailFromHeader(value)
		debugf("captured From header", "value", s.fromHeader)
	}
	return milter.RespContinue, nil
}

// Headers is called after all message headers are received.
func (s *milterSession) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	switch cfg.action {
	case actionDunno:
		return s.handleDunno()
	case actionQuarantineHeader:
		return s.handleQuarantineHeader()
	case actionReject:
		return s.handleReject()
	case actionDiscard:
		return s.handleDiscard()
	default:
		return milter.RespAccept, nil
	}
}

// runChecks performs check B (envelopeFrom domain vs From: header domain)
// and stores the result in s.flagCheckData.
func (s *milterSession) runChecks() {
	envDomain := extractDomain(s.envelopeFrom)
	fromDomain := extractDomainFromHeader(s.fromHeader)
	if strings.EqualFold(envDomain, fromDomain) {
		s.flagCheckData = checkPass
	} else {
		s.flagCheckData = checkFail
	}
}

func (s *milterSession) logResult(returnCode string) {
	slog.Info("milter",
		"envelope_from", s.envelopeFrom,
		"auth_user", s.authUser,
		"flag_check_auth", s.flagCheckAuth,
		"from_header", s.fromHeader,
		"flag_check_data", s.flagCheckData,
		"return_code", returnCode,
	)
}


func (s *milterSession) addHeaders(m *milter.Modifier, quarantineVal string) {
	if err := m.AddHeader(headerEnvelopeFrom, s.envelopeFrom); err != nil {
		slog.Error("failed to add "+headerEnvelopeFrom, "err", err)
	}
	if err := m.AddHeader(headerFrom, s.fromHeader); err != nil {
		slog.Error("failed to add "+headerFrom, "err", err)
	}
	if err := m.AddHeader(headerQuarantine, quarantineVal); err != nil {
		slog.Error("failed to add "+headerQuarantine, "err", err)
	}
}

func (s *milterSession) handleDunno() (milter.Response, error) {
	s.runChecks()
	s.logResult(actionDunno)
	return milter.RespAccept, nil
}

func (s *milterSession) handleQuarantineHeader() (milter.Response, error) {
	s.runChecks()
	s.logResult(actionDunno)
	// Continue to Body() to add headers.
	return milter.RespContinue, nil
}

func (s *milterSession) handleDiscard() (milter.Response, error) {
	s.runChecks()
	if s.flagCheckData == checkFail {
		s.logResult(actionDiscard)
		return milter.RespDiscard, nil
	}
	s.logResult(actionDunno)
	return milter.RespAccept, nil
}

func (s *milterSession) handleReject() (milter.Response, error) {
	s.runChecks()
	if s.flagCheckData == checkFail {
		s.logResult(actionReject)
		return rejectWith("MFC010002"), nil
	}
	s.logResult(actionDunno)
	return milter.RespAccept, nil
}

func (s *milterSession) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *milterSession) Body(m *milter.Modifier) (milter.Response, error) {
	if cfg.action == actionQuarantineHeader {
		quarantineVal := "no"
		if s.flagCheckAuth == checkFail || s.flagCheckData == checkFail {
			quarantineVal = "yes"
		}
		s.addHeaders(m, quarantineVal)
	}
	return milter.RespAccept, nil
}

func (s *milterSession) Abort(m *milter.Modifier) error {
	s.reset()
	return nil
}

// ---------------------------------------------------------------------------
// Domain extraction helpers
// ---------------------------------------------------------------------------

func extractDomain(addr string) string {
	addr = strings.Trim(addr, "<> \t")
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}

// extractEmailFromHeader extracts the email address from a From: header value.
// Handles: "Display Name <user@domain.com>", "<user@domain.com>", "user@domain.com".
func extractEmailFromHeader(header string) string {
	header = strings.TrimSpace(header)
	start := strings.LastIndex(header, "<")
	end := strings.LastIndex(header, ">")
	if start >= 0 && end > start {
		return strings.ToLower(strings.TrimSpace(header[start+1 : end]))
	}
	return strings.ToLower(strings.TrimSpace(header))
}

func extractDomainFromHeader(header string) string {
	return extractDomain(extractEmailFromHeader(header))
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
