package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTPOptions are notify's smtp entry. smtp_cc lists the recipients, as it
// does in notify.
type SMTPOptions struct {
	ID              string   `yaml:"id"`
	Server          string   `yaml:"smtp_server"`
	Username        string   `yaml:"smtp_username"`
	Password        string   `yaml:"smtp_password"`
	FromAddress     string   `yaml:"from_address"`
	SMTPCC          []string `yaml:"smtp_cc"`
	SMTPFormat      string   `yaml:"smtp_format"`
	Subject         string   `yaml:"subject"`
	HTML            bool     `yaml:"smtp_html"`
	DisableStartTLS bool     `yaml:"smtp_disable_starttls"`
}

type smtpProvider struct {
	env *Env
	counter
	opts []*SMTPOptions
}

func newSMTP(o []*SMTPOptions, ids []string, env *Env) *smtpProvider {
	s := &smtpProvider{env: env, opts: pick(o, func(x *SMTPOptions) string { return x.ID }, ids)}
	for _, x := range s.opts {
		env.Client.AddSecrets(x.Password)
	}
	return s
}

func (s *smtpProvider) Name() string { return "smtp" }
func (s *smtpProvider) entries() int { return len(s.opts) }

func (s *smtpProvider) Send(ctx context.Context, msg, cli string) []Delivery {
	n := s.next()
	var out []Delivery
	for _, o := range s.opts {
		d := Delivery{Provider: "smtp", ID: entryID(o.ID), Parts: len(o.SMTPCC)}
		text := FormatMessage(msg, SelectFormat(cli, o.SMTPFormat), n, s.env.now())
		if s.env.Client.Rate != nil {
			if err := s.env.Client.Rate.Wait(ctx); err != nil {
				d.Err = err
				out = append(out, d)
				continue
			}
		}
		if err := sendMail(ctx, o, text); err != nil {
			d.Err = errors.New(s.env.Client.scrub(err.Error(), nil))
		}
		out = append(out, d)
	}
	return out
}

// sendMail sends one mail to each recipient in one session, as shoutrrr
// does: STARTTLS when the server offers it (a server that does not is used
// in the clear, and the mail says nothing of it), PLAIN authentication
// when there is a username, and implicit TLS on port 465.
func sendMail(ctx context.Context, o *SMTPOptions, text string) error {
	if o.Server == "" {
		return errors.New("smtp_server is empty")
	}
	if o.FromAddress == "" {
		return errors.New("from_address is empty")
	}
	if len(o.SMTPCC) == 0 {
		return errors.New("smtp_cc lists no recipient")
	}
	host, port, err := net.SplitHostPort(o.Server)
	if err != nil {
		host, port = o.Server, "25"
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	var conn net.Conn
	if port == "465" {
		conn, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		return fmt.Errorf("could not connect to %s: %w", net.JoinHostPort(host, port), err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if !o.DisableStartTLS && port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return fmt.Errorf("smtp STARTTLS: %w", err)
			}
		}
	}
	if o.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", o.Username, o.Password, host)); err != nil {
			return fmt.Errorf("smtp authentication: %w", err)
		}
	}
	for _, to := range o.SMTPCC {
		if err := c.Mail(o.FromAddress); err != nil {
			return fmt.Errorf("smtp sender %s: %w", o.FromAddress, err)
		}
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("smtp recipient %s: %w", to, err)
		}
		w, err := c.Data()
		if err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}
		if _, err := io.WriteString(w, mailBody(o, to, text)); err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("smtp message to %s: %w", to, err)
		}
	}
	return c.Quit()
}

// mailBody is the header and body of one mail. With smtp_html the text goes
// out as a plain part and as an HTML part, as shoutrrr sends it.
func mailBody(o *SMTPOptions, to, text string) string {
	var b strings.Builder
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("Subject", mime.QEncoding.Encode("UTF-8", o.Subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("To", to)
	h("From", o.FromAddress)
	h("MIME-version", "1.0")
	if !o.HTML {
		h("Content-Type", `text/plain; charset="UTF-8"`)
		b.WriteString("\r\n" + text)
		return b.String()
	}
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	boundary := fmt.Sprintf("%x", raw)
	h("Content-Type", "multipart/alternative; boundary="+boundary)
	b.WriteString("\r\n")
	for _, ct := range []string{`text/plain; charset="UTF-8"`, `text/html; charset="UTF-8"`} {
		b.WriteString("\r\n\r\n--" + boundary + "\r\nContent-Type: " + ct + "\r\n\r\n" + text)
	}
	b.WriteString("\r\n\r\n--" + boundary + "--")
	return b.String()
}
