package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/wneessen/go-mail"
)

type GoMailSender struct{}

func NewGoMailSender() *GoMailSender {
	return &GoMailSender{}
}

func (s *GoMailSender) Send(ctx context.Context, cfg MailerConfig, msg MailMessage) error {
	host := strings.TrimSpace(cfg.Host)
	to := strings.TrimSpace(msg.To)
	from := strings.TrimSpace(cfg.Username)
	if host == "" || to == "" || from == "" {
		return fmt.Errorf("missing mail configuration")
	}

	port, useSSL, tlsPolicy := resolveSMTPTransport(cfg.Port)
	opts := []mail.Option{
		mail.WithPort(port),
		mail.WithTimeout(10 * time.Second),
		mail.WithTLSPortPolicy(tlsPolicy),
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
	}
	if useSSL {
		opts = append(opts, mail.WithSSLPort(false))
	}

	if strings.TrimSpace(cfg.Username) != "" {
		opts = append(opts, mail.WithUsername(strings.TrimSpace(cfg.Username)))
	}
	if cfg.Password != "" {
		opts = append(opts, mail.WithPassword(cfg.Password))
	}

	client, err := mail.NewClient(host, opts...)
	if err != nil {
		return err
	}
	if err := client.DialWithContext(ctx); err != nil {
		return err
	}
	defer client.Close()

	m := mail.NewMsg()
	if err := m.From(from); err != nil {
		return err
	}
	if err := m.To(to); err != nil {
		return err
	}
	m.Subject(strings.TrimSpace(msg.Subject))
	if strings.TrimSpace(msg.HTMLBody) != "" {
		m.SetBodyString(mail.TypeTextHTML, msg.HTMLBody)
	} else {
		m.SetBodyString(mail.TypeTextPlain, msg.TextBody)
	}
	return client.Send(m)
}

func defaultPort(port int) int {
	if port > 0 {
		return port
	}
	return 587
}

func resolveSMTPTransport(configuredPort int) (port int, sslPort bool, tlsPolicy mail.TLSPolicy) {
	port = defaultPort(configuredPort)

	switch port {
	case 465:
		// Port 465 uses implicit SSL/TLS (SMTPS).
		return port, true, mail.NoTLS
	case 25:
		// Port 25 often runs plain SMTP and may optionally support STARTTLS.
		return port, false, mail.TLSOpportunistic
	default:
		// Default to STARTTLS-required behavior on modern submission ports (e.g. 587).
		return port, false, mail.TLSMandatory
	}
}
