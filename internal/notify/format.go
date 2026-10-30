package notify

import (
	"fmt"
	"strings"
	"time"
)

// FormatMessage fills notify's message variables: {{data}} is the message,
// {{date}}, {{time}} and {{datetime}} the moment it is sent, {{count}} how
// many messages the provider has sent, this one included. Logic from
// projectdiscovery/notify (MIT), pkg/utils/utils.go. One pass, so a
// message that itself holds {{count}} is left alone.
func FormatMessage(msg, format string, counter int, now time.Time) string {
	return strings.NewReplacer(
		"{{datetime}}", now.Format("01-02-2006 15:04:05-0700"),
		"{{date}}", now.Format("01-02-2006"),
		"{{time}}", now.Format("15:04:05-0700"),
		"{{count}}", fmt.Sprint(counter),
		"{{data}}", msg,
	).Replace(format)
}

// SelectFormat picks the format: the command line's, else the provider's,
// else {{data}}.
func SelectFormat(cli, config string) string {
	switch {
	case cli != "":
		return cli
	case config != "":
		return config
	}
	return "{{data}}"
}
