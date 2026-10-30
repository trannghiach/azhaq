package notify

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"
)

// smtpSink accepts mail on 127.0.0.1 and keeps each transaction.
type smtpSink struct {
	ln    net.Listener
	mails chan sinkMail
}

type sinkMail struct {
	From, To string
	Data     string
	Auth     string
}

func newSMTPSink(t *testing.T) *smtpSink {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpSink{ln: ln, mails: make(chan sinkMail, 10)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *smtpSink) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(f string, a ...any) { fmt.Fprintf(c, f+"\r\n", a...) }
	say("220 sink ESMTP")
	var cur sinkMail
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch cmd := strings.ToUpper(line); {
		case strings.HasPrefix(cmd, "EHLO"):
			say("250-sink")
			say("250 AUTH PLAIN")
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			cur.Auth = line
			say("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			cur.From = strings.Trim(line[len("MAIL FROM:"):], "<> ")
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			cur.To = strings.Trim(line[len("RCPT TO:"):], "<> ")
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			cur.Data = b.String()
			s.mails <- cur
			cur = sinkMail{Auth: cur.Auth}
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func TestSMTPSendsOneMailPerRecipient(t *testing.T) {
	sink := newSMTPSink(t)
	pc, err := ParseConfig(strings.NewReader(fmt.Sprintf(`
smtp:
  - id: mail
    smtp_server: %s
    smtp_username: bot
    smtp_password: pw-123456
    from_address: azhaq@example.test
    smtp_cc: [a@example.test, b@example.test]
    subject: "Recon: new hosts ✓"
    smtp_format: "found: {{data}}"
`, sink.ln.Addr())), "t")
	if err != nil {
		t.Fatal(err)
	}
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: &Client{}})
	for _, d := range set.Send(context.Background(), "x.example.test") {
		if d.Err != nil {
			t.Fatal(d.Err)
		}
	}
	var got []sinkMail
	for i := 0; i < 2; i++ {
		select {
		case m := <-sink.mails:
			got = append(got, m)
		case <-time.After(3 * time.Second):
			t.Fatalf("%d mails", i)
		}
	}
	for i, to := range []string{"a@example.test", "b@example.test"} {
		m := got[i]
		if m.From != "azhaq@example.test" || m.To != to || !strings.HasPrefix(m.Auth, "AUTH PLAIN ") {
			t.Errorf("%+v", m)
		}
		msg, err := mail.ReadMessage(strings.NewReader(m.Data))
		if err != nil {
			t.Fatal(err)
		}
		subj, _ := (&mimeDecoder).DecodeHeader(msg.Header.Get("Subject"))
		body := new(strings.Builder)
		_, _ = bufioCopy(body, msg.Body)
		if subj != "Recon: new hosts ✓" || msg.Header.Get("To") != to || msg.Header.Get("From") != "azhaq@example.test" ||
			!strings.HasPrefix(msg.Header.Get("Content-Type"), "text/plain") || strings.TrimSpace(body.String()) != "found: x.example.test" {
			t.Errorf("subject %q headers %v body %q", subj, msg.Header, body)
		}
	}
}

func TestSMTPHTMLIsMultipart(t *testing.T) {
	sink := newSMTPSink(t)
	pc, _ := ParseConfig(strings.NewReader(fmt.Sprintf("smtp:\n  - smtp_server: %s\n    from_address: f@x.test\n    smtp_cc: [t@x.test]\n    smtp_html: true\n    subject: s\n", sink.ln.Addr())), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: &Client{}})
	if d := set.Send(context.Background(), "<b>hi</b>"); d[0].Err != nil {
		t.Fatal(d[0].Err)
	}
	m := <-sink.mails
	if !strings.Contains(m.Data, "multipart/alternative; boundary=") || !strings.Contains(m.Data, "text/html; charset=") || strings.Count(m.Data, "<b>hi</b>") != 2 {
		t.Errorf("%q", m.Data)
	}
}

func TestSMTPFailureIsReported(t *testing.T) {
	pc, _ := ParseConfig(strings.NewReader("smtp:\n  - smtp_server: 127.0.0.1:1\n    smtp_password: SECRETPW\n    from_address: f@x.test\n    smtp_cc: [t@x.test]\n"), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: &Client{}})
	if d := set.Send(context.Background(), "x"); d[0].Err == nil {
		t.Error("a mail server that is not there is a failure")
	}
}
