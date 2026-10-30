package fuzz

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strconv"
	"strings"
	"time"
)

// The report files of -o and -of are ffuf's: the same formats, field names
// and columns, so a script written for its reports reads these. The JSON,
// CSV, markdown and HTML writers follow github.com/ffuf/ffuf's pkg/output
// (MIT licence, Joona Hoikkala and contributors).

// Formats are the values of -of.
var Formats = []string{"json", "ejson", "html", "md", "csv", "ecsv", "all"}

// ReportConfig is the "config" object of a JSON report: ffuf's field names,
// filled with what this run was given. A field of an ffuf option azhaq does
// not have holds its default.
type ReportConfig struct {
	AutoCalibration           bool              `json:"autocalibration"`
	AutoCalibrationKeyword    string            `json:"autocalibration_keyword"`
	AutoCalibrationPerHost    bool              `json:"autocalibration_perhost"`
	AutoCalibrationStrategies []string          `json:"autocalibration_strategies"`
	AutoCalibrationStrings    []string          `json:"autocalibration_strings"`
	Colors                    bool              `json:"colors"`
	CommandLine               string            `json:"cmdline"`
	ConfigFile                string            `json:"configfile"`
	Data                      string            `json:"postdata"`
	Debuglog                  string            `json:"debuglog"`
	Delay                     ReportDelay       `json:"delay"`
	DirSearchCompat           bool              `json:"dirsearch_compatibility"`
	Encoders                  []string          `json:"encoders"`
	Extensions                []string          `json:"extensions"`
	FilterMode                string            `json:"fmode"`
	FollowRedirects           bool              `json:"follow_redirects"`
	Headers                   map[string]string `json:"headers"`
	IgnoreBody                bool              `json:"ignorebody"`
	IgnoreWordlistComments    bool              `json:"ignore_wordlist_comments"`
	InputMode                 string            `json:"inputmode"`
	InputNum                  int               `json:"cmd_inputnum"`
	InputProviders            []ReportProvider  `json:"inputproviders"`
	InputShell                string            `json:"inputshell"`
	Json                      bool              `json:"json"`
	Matchers                  ReportMatchers    `json:"matchers"`
	MatcherMode               string            `json:"mmode"`
	MaxTime                   int               `json:"maxtime"`
	MaxTimeJob                int               `json:"maxtime_job"`
	Method                    string            `json:"method"`
	Noninteractive            bool              `json:"noninteractive"`
	OutputDirectory           string            `json:"outputdirectory"`
	OutputFile                string            `json:"outputfile"`
	OutputFormat              string            `json:"outputformat"`
	OutputSkipEmptyFile       bool              `json:"OutputSkipEmptyFile"`
	ProxyURL                  string            `json:"proxyurl"`
	Quiet                     bool              `json:"quiet"`
	Rate                      int64             `json:"rate"`
	Raw                       bool              `json:"raw"`
	Recursion                 bool              `json:"recursion"`
	RecursionDepth            int               `json:"recursion_depth"`
	RecursionStrategy         string            `json:"recursion_strategy"`
	ReplayProxyURL            string            `json:"replayproxyurl"`
	RequestFile               string            `json:"requestfile"`
	RequestProto              string            `json:"requestproto"`
	ScraperFile               string            `json:"scraperfile"`
	Scrapers                  string            `json:"scrapers"`
	SNI                       string            `json:"sni"`
	StopOn403                 bool              `json:"stop_403"`
	StopOnAll                 bool              `json:"stop_all"`
	StopOnErrors              bool              `json:"stop_errors"`
	Threads                   int               `json:"threads"`
	Timeout                   int               `json:"timeout"`
	Url                       string            `json:"url"`
	Verbose                   bool              `json:"verbose"`
	Wordlists                 []string          `json:"wordlists"`
	Http2                     bool              `json:"http2"`
	ClientCert                string            `json:"client-cert"`
	ClientKey                 string            `json:"client-key"`
}

// ReportDelay is -p as ffuf writes it: "0.10" or "0.10-0.50".
type ReportDelay struct {
	Value string `json:"value"`
}

// ReportProvider is one wordlist or command in the config.
type ReportProvider struct {
	Name     string `json:"name"`
	Keyword  string `json:"keyword"`
	Value    string `json:"value"`
	Encoders string `json:"encoders"`
	Template string `json:"template"`
}

type reportValue struct {
	Value string `json:"value"`
}

// ReportMatchers is the matchers and filters at the end of the run, those
// calibration added included.
type ReportMatchers struct {
	IsCalibrated     bool                       `json:"IsCalibrated"`
	Mutex            struct{}                   `json:"Mutex"`
	Matchers         map[string]reportValue     `json:"Matchers"`
	Filters          map[string]reportValue     `json:"Filters"`
	PerDomainFilters map[string]perDomainFilter `json:"PerDomainFilters"`
}

type perDomainFilter struct {
	IsCalibrated bool                   `json:"IsCalibrated"`
	Filters      map[string]reportValue `json:"Filters"`
}

// Describe is the set as a report shows it.
func (s *Set) Describe(calibrated bool) ReportMatchers {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := ReportMatchers{IsCalibrated: calibrated, Matchers: map[string]reportValue{}, Filters: map[string]reportValue{}, PerDomainFilters: map[string]perDomainFilter{}}
	for k, f := range s.matchers {
		out.Matchers[k] = reportValue{f.Repr()}
	}
	for k, f := range s.filters {
		out.Filters[k] = reportValue{f.Repr()}
	}
	for host, fs := range s.hostFilters {
		d := perDomainFilter{IsCalibrated: true, Filters: map[string]reportValue{}}
		for k, f := range fs {
			d.Filters[k] = reportValue{f.Repr()}
		}
		out.PerDomainFilters[host] = d
	}
	return out
}

// Report is what a report file holds.
type Report struct {
	CommandLine string
	Config      ReportConfig
	Keywords    []string // in the order of the wordlists
	Results     []Result
	Time        time.Time
}

// jsonResult is one result of -of json: ffuf's keys and order.
type jsonResult struct {
	Input            map[string]string   `json:"input"`
	Position         int                 `json:"position"`
	StatusCode       int                 `json:"status"`
	ContentLength    int64               `json:"length"`
	ContentWords     int64               `json:"words"`
	ContentLines     int64               `json:"lines"`
	ContentType      string              `json:"content-type"`
	RedirectLocation string              `json:"redirectlocation"`
	ScraperData      map[string][]string `json:"scraper"`
	Duration         int64               `json:"duration"`
	ResultFile       string              `json:"resultfile"`
	Url              string              `json:"url"`
	Host             string              `json:"host"`
}

// ejsonResult is the same with the inputs in base64, as -json prints them.
type ejsonResult struct {
	Input            map[string][]byte   `json:"input"`
	Position         int                 `json:"position"`
	StatusCode       int                 `json:"status"`
	ContentLength    int64               `json:"length"`
	ContentWords     int64               `json:"words"`
	ContentLines     int64               `json:"lines"`
	ContentType      string              `json:"content-type"`
	RedirectLocation string              `json:"redirectlocation"`
	Url              string              `json:"url"`
	Duration         int64               `json:"duration"`
	ScraperData      map[string][]string `json:"scraper"`
	ResultFile       string              `json:"resultfile"`
	Host             string              `json:"host"`
}

// StdoutJSON is a result as one line of -json shows it: ffuf's fields, the
// inputs in base64.
func StdoutJSON(r Result) ejsonResult {
	in := make(map[string][]byte, len(r.Input))
	for k, v := range r.Input {
		in[k] = []byte(v)
	}
	return ejsonResult{Input: in, Position: r.Position, StatusCode: r.Status, ContentLength: r.Length, ContentWords: r.Words, ContentLines: r.Lines,
		ContentType: r.ContentType, RedirectLocation: r.RedirectLocation, Url: r.URL, Duration: r.Duration, ScraperData: map[string][]string{},
		ResultFile: r.ResultFile, Host: r.Host}
}

// WriteReport writes the report in format (json, ejson, html, md, csv, ecsv),
// or all of them to path with their suffixes (all).
func WriteReport(path, format string, r Report) error {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	if format == "all" {
		var firstErr error
		for _, f := range []string{"json", "ejson", "html", "md", "csv", "ecsv"} {
			if err := WriteReport(path+"."+f, f, r); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	switch format {
	case "json":
		return writeJSON(path, r)
	case "ejson":
		return writeEJSON(path, r)
	case "csv":
		return writeCSV(path, r, false)
	case "ecsv":
		return writeCSV(path, r, true)
	case "html":
		return writeHTML(path, r)
	case "md":
		return writeMarkdown(path, r)
	}
	return fmt.Errorf("-of %q: one of %s", format, strings.Join(Formats, ", "))
}

func writeJSON(path string, r Report) error {
	rows := make([]jsonResult, 0, len(r.Results))
	for _, x := range r.Results {
		rows = append(rows, jsonResult{Input: x.Input, Position: x.Position, StatusCode: x.Status, ContentLength: x.Length, ContentWords: x.Words,
			ContentLines: x.Lines, ContentType: x.ContentType, RedirectLocation: x.RedirectLocation, ScraperData: map[string][]string{},
			Duration: x.Duration, ResultFile: x.ResultFile, Url: x.URL, Host: x.Host})
	}
	return writeJSONFile(path, struct {
		CommandLine string        `json:"commandline"`
		Time        string        `json:"time"`
		Results     []jsonResult  `json:"results"`
		Config      *ReportConfig `json:"config"`
	}{r.CommandLine, r.Time.Format(time.RFC3339), rows, &r.Config})
}

func writeEJSON(path string, r Report) error {
	rows := make([]ejsonResult, 0, len(r.Results))
	for _, x := range r.Results {
		rows = append(rows, StdoutJSON(x))
	}
	return writeJSONFile(path, struct {
		CommandLine string        `json:"commandline"`
		Time        string        `json:"time"`
		Results     []ejsonResult `json:"results"`
		Config      *ReportConfig `json:"config"`
	}{CommandLine: r.CommandLine, Time: r.Time.Format(time.RFC3339), Results: rows})
}

func writeJSONFile(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0644)
}

var csvStatic = []string{"url", "redirectlocation", "position", "status_code", "content_length", "content_words", "content_lines", "content_type", "duration", "resultfile", "Ffufhash"}

func writeCSV(path string, r Report, encode bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(append(append([]string{}, r.Keywords...), csvStatic...)); err != nil {
		return err
	}
	for _, x := range r.Results {
		var row []string
		for _, k := range r.Keywords {
			v := x.Input[k]
			if encode {
				v = base64.StdEncoding.EncodeToString([]byte(v))
			}
			row = append(row, v)
		}
		row = append(row, x.URL, x.RedirectLocation, strconv.Itoa(x.Position), strconv.Itoa(x.Status), strconv.FormatInt(x.Length, 10),
			strconv.FormatInt(x.Words, 10), strconv.FormatInt(x.Lines, 10), x.ContentType, time.Duration(x.Duration).String(), x.ResultFile, x.Input["FFUFHASH"])
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

type pageRow struct {
	Values           []string
	Position         int
	StatusCode       int
	ContentLength    int64
	ContentWords     int64
	ContentLines     int64
	ContentType      string
	RedirectLocation string
	ScraperData      string
	Duration         time.Duration
	ResultFile       string
	Url              string
	Host             string
	HTMLColor        string
	FfufHash         string
}

type page struct {
	CommandLine string
	Time        string
	Keys        []string
	Results     []pageRow
}

func pageOf(r Report) page {
	p := page{CommandLine: r.CommandLine, Time: r.Time.Format(time.RFC3339), Keys: r.Keywords}
	for _, x := range r.Results {
		row := pageRow{Position: x.Position, StatusCode: x.Status, ContentLength: x.Length, ContentWords: x.Words, ContentLines: x.Lines,
			ContentType: x.ContentType, RedirectLocation: x.RedirectLocation, Duration: time.Duration(x.Duration), ResultFile: x.ResultFile,
			Url: x.URL, Host: x.Host, FfufHash: x.Input["FFUFHASH"], HTMLColor: statusColor(x.Status)}
		for _, k := range r.Keywords {
			row.Values = append(row.Values, x.Input[k])
		}
		p.Results = append(p.Results, row)
	}
	return p
}

func statusColor(s int) string {
	switch {
	case s >= 200 && s <= 299:
		return "#adea9e"
	case s >= 300 && s <= 399:
		return "#bbbbe6"
	case s >= 400 && s <= 499:
		return "#d2cb7e"
	case s >= 500 && s <= 599:
		return "#de8dc1"
	}
	return "black"
}

func writeHTML(path string, r Report) error {
	return writePage(path, "output.html", htmlTemplate, pageOf(r))
}

const markdownTemplate = `# FFUF Report

  Command line : ` + "`{{.CommandLine}}`" + `
  Time: ` + "{{ .Time }}" + `

  {{ range .Keys }}| {{ . }} {{ end }}| URL | Redirectlocation | Position | Status Code | Content Length | Content Words | Content Lines | Content Type | Duration | ResultFile | ScraperData | Ffufhash
  {{ range .Keys }}| :- {{ end }}| :-- | :--------------- | :---- | :------- | :---------- | :------------- | :------------ | :--------- | :----------- | :------------ | :-------- |
  {{range .Results}}{{ range $value := .Values }}| {{ $value | printf "%s" }} {{ end }}| {{ .Url }} | {{ .RedirectLocation }} | {{ .Position }} | {{ .StatusCode }} | {{ .ContentLength }} | {{ .ContentWords }} | {{ .ContentLines }} | {{ .ContentType }} | {{ .Duration}} | {{ .ResultFile }} | {{ .ScraperData }} | {{ .FfufHash }}
  {{end}}`

func writeMarkdown(path string, r Report) error {
	return writePage(path, "output.md", markdownTemplate, pageOf(r))
}

func writePage(path, name, text string, p page) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	t, err := template.New(name).Delims("{{", "}}").Parse(text)
	if err != nil {
		return err
	}
	return t.Execute(f, p)
}
