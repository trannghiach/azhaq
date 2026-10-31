package egress

import "crypto/tls"

func tlsNamed(name string) *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: name}
}
