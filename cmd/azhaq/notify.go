package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/notify"
)

// cmdNotify is projectdiscovery's notify: text from a file or a pipe, one
// message per line (or packed into as few as fit with -bulk), to the
// providers a provider-config.yaml names. The file and the flags are
// notify's own; a delivery that failed is a failure in the summary and
// exit 3, where notify prints a line and exits 0.
func cmdNotify(args []string) error {
	fs := newFlags("notify")
	var o notifyOpts
	o.register(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if o.version {
		fmt.Printf("azhaq notify (azhaq %s)\n", version)
		return nil
	}
	if err := o.applyConfig(fs); err != nil {
		return err
	}
	if o.verbose && o.silent {
		return usagef("-v and -silent cannot both be given")
	}
	if o.charLimit <= 3 {
		return usagef("-char-limit must be above 3")
	}
	set, client, err := o.build()
	if err != nil {
		return err
	}
	in, closeIn, err := o.input()
	if err != nil {
		return err
	}
	defer closeIn()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if o.verbose {
		client.Verbose = func(s string) { fmt.Fprintf(os.Stderr, "azhaq notify: %s\n", s) }
	}

	rep := newReport("notify")
	rep.what = "messages"
	rep.Counts = map[string]int{}
	fails := map[string]*engine.Failure{}
	var failOrder []string
	enc := json.NewEncoder(os.Stdout)
	err = notify.Messages(in, o.charLimit, o.bulk, func(msg string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if o.delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(o.delay * float64(time.Second))):
			}
		}
		rep.Results++
		ds := set.Send(ctx, msg)
		type sent struct {
			Provider string `json:"provider"`
			ID       string `json:"id"`
		}
		var okList []sent
		var failList []map[string]string
		for _, d := range ds {
			if d.Err == nil {
				rep.Counts["delivered"]++
				if d.Tries > 0 {
					rep.Counts["retried"]++
				}
				okList = append(okList, sent{d.Provider, d.ID})
				if o.verbose {
					fmt.Fprintf(os.Stderr, "azhaq notify: %s notification sent for id: %s\n", d.Provider, d.ID)
				}
				continue
			}
			failList = append(failList, map[string]string{"provider": d.Provider, "id": d.ID, "error": d.Err.Error()})
			key := d.Provider + "\x00" + d.Err.Error()
			f := fails[key]
			if f == nil {
				f = &engine.Failure{Collector: d.Provider, Error: d.Err.Error()}
				fails[key] = f
				failOrder = append(failOrder, key)
			}
			f.Count++
			if len(f.Targets) < 100 && !containsStr(f.Targets, d.ID) {
				f.Targets = append(f.Targets, "id "+d.ID)
			}
		}
		if o.json {
			return enc.Encode(map[string]any{"message": msg, "sent": okList, "failed": failList})
		}
		_, err := fmt.Fprintln(os.Stdout, msg)
		return err
	})
	for _, k := range failOrder {
		rep.Failed = append(rep.Failed, *fails[k])
	}
	if rep.Counts["retried"] == 0 {
		delete(rep.Counts, "retried")
	}
	if len(rep.Counts) == 0 {
		rep.Counts = nil
	}
	if err != nil {
		if ctx.Err() != nil {
			rep.Stopped = "interrupted"
			rep.Notes = append(rep.Notes, "stopped by Ctrl-C: messages after "+strconv.Itoa(rep.Results)+" were not sent")
			return rep.finish(o.json, o.silent)
		}
		return err
	}
	if rep.Results == 0 {
		rep.Notes = append(rep.Notes, "the input held no message: nothing was sent")
	}
	return rep.finish(o.json, o.silent)
}

func containsStr(xs []string, x string) bool {
	for _, y := range xs {
		if y == "id "+x {
			return true
		}
	}
	return false
}

// notifyOpts are notify's flags, under notify's names and its short ones.
type notifyOpts struct {
	config, providerConfig, data, msgFormat, proxy string
	providers, ids                                 stringsFlag
	rate, charLimit                                int
	delay                                          float64
	bulk, silent, verbose, version, noColor, duc   bool
	json                                           bool
}

func (o *notifyOpts) register(fs *flag.FlagSet) {
	str := func(p *string, long, short, usage string) {
		fs.StringVar(p, long, "", usage)
		if short != "" {
			fs.StringVar(p, short, "", "short for -"+long)
		}
	}
	boolean := func(p *bool, long, short, usage string) {
		fs.BoolVar(p, long, false, usage)
		if short != "" {
			fs.BoolVar(p, short, false, "short for -"+long)
		}
	}
	str(&o.config, "config", "", "notify configuration file: YAML of these flags, by their long names ($HOME/.config/notify/config.yaml when it exists); a flag given here wins")
	str(&o.providerConfig, "provider-config", "pc", "provider config path (default: $HOME/.config/azhaq/notify.yaml, else notify's $HOME/.config/notify/provider-config.yaml); notify's schema, words starting with $ replaced by that variable")
	str(&o.data, "data", "i", "input file to send for notify (default: standard input)")
	fs.Var(&o.providers, "provider", "provider to send the notification to: slack, discord, pushover, googlechat, smtp, teams, telegram, custom, gotify (repeatable or comma-separated)")
	fs.Var(&o.providers, "p", "short for -provider")
	fs.Var(&o.ids, "id", "send only to the configured entries with this id (repeatable or comma-separated)")
	fs.IntVar(&o.rate, "rate-limit", 1, "maximum number of requests to send per second (0: no limit)")
	fs.IntVar(&o.rate, "rl", 1, "short for -rate-limit")
	fs.Float64Var(&o.delay, "delay", 0, "delay in seconds before each message")
	fs.Float64Var(&o.delay, "d", 0, "short for -delay")
	boolean(&o.bulk, "bulk", "", "pack lines into messages of up to -char-limit characters instead of one message per line")
	fs.IntVar(&o.charLimit, "char-limit", 4000, "max character limit per message: a longer line goes out in pieces that end in ...")
	fs.IntVar(&o.charLimit, "cl", 4000, "short for -char-limit")
	str(&o.msgFormat, "msg-format", "mf", "format of each message: {{data}}, {{date}}, {{time}}, {{datetime}}, {{count}}; wins over the provider's *_format")
	boolean(&o.silent, "silent", "", "no summary unless something failed")
	boolean(&o.verbose, "verbose", "v", "log each delivery and each retry")
	boolean(&o.version, "version", "", "print the version")
	boolean(&o.noColor, "no-color", "nc", "accepted and ignored: azhaq prints no colour")
	boolean(&o.duc, "disable-update-check", "duc", "accepted and ignored: azhaq never checks for updates")
	str(&o.proxy, "proxy", "", "HTTP or SOCKS5 proxy URL for the notification requests (default: the environment's); certificates are verified")
	fs.BoolVar(&o.json, "json", false, "one JSON object per message on standard output, the summary as JSON on standard error")
}

// applyConfig fills the flags the command line left out from the config
// file, as goflags does for notify.
func (o *notifyOpts) applyConfig(fs *flag.FlagSet) error {
	path, explicit := o.config, o.config != ""
	if !explicit {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		path = filepath.Join(home, ".config", "notify", "config.yaml")
		if _, err := os.Stat(path); err != nil {
			return nil
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return usagef("-config: %v", err)
	}
	var kv map[string]any
	if err := yaml.Unmarshal(raw, &kv); err != nil {
		return usagef("%s: %v", path, err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	aliases := map[string]string{"pc": "provider-config", "i": "data", "p": "provider", "rl": "rate-limit", "d": "delay", "cl": "char-limit", "mf": "msg-format", "v": "verbose", "nc": "no-color", "duc": "disable-update-check", "up": "update"}
	long := func(n string) string {
		if l, ok := aliases[n]; ok {
			return l
		}
		return n
	}
	givenLong := map[string]bool{}
	for n := range set {
		givenLong[long(n)] = true
	}
	for key, v := range kv {
		name := long(strings.ReplaceAll(key, "_", "-"))
		if name == "config" || name == "update" {
			continue
		}
		f := fs.Lookup(name)
		if f == nil || name == "json" {
			return usagef("%s: %q is not a notify option", path, key)
		}
		if givenLong[name] {
			continue
		}
		var vals []string
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				vals = append(vals, fmt.Sprint(e))
			}
		default:
			vals = []string{fmt.Sprint(x)}
		}
		for _, s := range vals {
			if err := fs.Set(name, s); err != nil {
				return usagef("%s: %s: %v", path, key, err)
			}
		}
		if verboseConfig(o) {
			fmt.Fprintf(os.Stderr, "azhaq notify: %s: %s\n", path, key)
		}
	}
	return nil
}

func verboseConfig(o *notifyOpts) bool { return o.verbose }

// build makes the provider set and the client the flags describe.
func (o *notifyOpts) build() (*notify.Set, *notify.Client, error) {
	path, err := o.providerConfigPath()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := notify.LoadConfig(path)
	if err != nil {
		return nil, nil, usagef("provider config: %v", err)
	}
	client, err := notify.NewClient(float64(o.rate), o.proxy)
	if err != nil {
		return nil, nil, usagef("%v", err)
	}
	names := commaList(o.providers)
	for i, n := range names {
		names[i] = strings.ToLower(n)
	}
	set, err := notify.NewSet(cfg, names, commaList(o.ids), o.msgFormat, &notify.Env{Client: client})
	if err != nil {
		return nil, nil, usagef("-provider: %v", err)
	}
	if set.Entries() == 0 {
		return nil, nil, usagef("%s: no provider entry matches (-provider %q, -id %q): nothing would be sent", path, strings.Join(names, ","), strings.Join(commaList(o.ids), ","))
	}
	return set, client, nil
}

func commaList(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// providerConfigPath is -provider-config, else azhaq's own file, else notify's.
func (o *notifyOpts) providerConfigPath() (string, error) {
	if o.providerConfig != "" {
		return o.providerConfig, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", usagef("give -provider-config FILE: %v", err)
	}
	for _, p := range []string{filepath.Join(home, ".config", "azhaq", "notify.yaml"), filepath.Join(home, ".config", "notify", "provider-config.yaml")} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", usagef("no provider config: give -provider-config FILE (notify's provider-config.yaml), or write one at ~/.config/azhaq/notify.yaml")
}

// input is -data, else standard input when something is piped into it.
func (o *notifyOpts) input() (io.Reader, func(), error) {
	switch {
	case o.data != "":
		f, err := os.Open(o.data)
		if err != nil {
			return nil, nil, usagef("%v", err)
		}
		return f, func() { f.Close() }, nil
	case stdinPiped():
		return os.Stdin, func() {}, nil
	}
	return nil, nil, usagef("notify works with standard input or a file: pipe text into it or give -data FILE")
}

// hooksFrom gathers the webhook URLs of watch -notify: each flag value is a
// URL or @FILE, a file with one URL a line (# starts a comment), so a
// token need not stand on a command line where ps shows it; the
// environment variable AZHAQ_NOTIFY holds more, one per comma or line.
func hooksFrom(flags []string, env string) ([]string, error) {
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	for _, v := range flags {
		path, isFile := strings.CutPrefix(v, "@")
		if !isFile {
			add(v)
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, usagef("-notify @%s: %v", path, err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			add(l)
		}
	}
	for _, l := range strings.FieldsFunc(env, func(r rune) bool { return r == ',' || r == '\n' }) {
		add(l)
	}
	return out, nil
}

// notifier sends a watch run's change set to the webhooks and providers
// the flags name.
type notifier struct {
	hooks  []string
	set    *notify.Set // nil without -notify-config
	client *notify.Client
	format string
	lines  int
	count  int // messages sent, for {{count}}
}

func newNotifier(hooks []string, config string, providers, ids []string, format string, rate float64, proxy string, lines int) (*notifier, error) {
	n := &notifier{hooks: hooks, format: format, lines: lines}
	if len(hooks) == 0 && config == "" {
		return n, nil
	}
	client, err := notify.NewClient(rate, proxy)
	if err != nil {
		return nil, usagef("-notify-proxy: %v", err)
	}
	n.client = client
	if config != "" {
		cfg, err := notify.LoadConfig(config)
		if err != nil {
			return nil, usagef("-notify-config: %v", err)
		}
		names := commaList(providers)
		for i, p := range names {
			names[i] = strings.ToLower(p)
		}
		if n.set, err = notify.NewSet(cfg, names, commaList(ids), format, &notify.Env{Client: client}); err != nil {
			return nil, usagef("-notify-provider: %v", err)
		}
		if n.set.Entries() == 0 {
			return nil, usagef("-notify-config %s: no provider entry matches: nothing would be sent", config)
		}
	}
	return n, nil
}

// send delivers ch and returns a line for each delivery that failed; no
// line holds a webhook URL or a token.
func (n *notifier) send(ctx context.Context, ch changes) []string {
	if n.client == nil {
		return nil
	}
	var lost []string
	text := ch.notifyText(n.lines)
	n.count++
	for _, h := range n.hooks {
		msg := text
		if n.format != "" {
			msg = notify.FormatMessage(text, n.format, n.count, time.Now())
		}
		if err := n.client.Send(ctx, h, msg, ch); err != nil {
			lost = append(lost, err.Error())
		}
	}
	if n.set != nil {
		for _, d := range n.set.Send(ctx, text) {
			if d.Err != nil {
				lost = append(lost, fmt.Sprintf("%s (id %s): %v", d.Provider, d.ID, d.Err))
			}
		}
	}
	return lost
}
