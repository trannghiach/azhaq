package fuzz

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Encoders are ffuf's -enc transforms (its pencode set), done here so
// the same -enc chains give the same words. A chain is applied to a word
// before it is put in the request.

type encoder func([]byte) ([]byte, error)

var encoders = map[string]encoder{
	"b64encode": func(b []byte) ([]byte, error) { return []byte(base64.StdEncoding.EncodeToString(b)), nil },
	"b64decode": func(b []byte) ([]byte, error) { return base64.StdEncoding.DecodeString(string(b)) },
	"hexencode": func(b []byte) ([]byte, error) { return []byte(hex.EncodeToString(b)), nil },
	"hexdecode": func(b []byte) ([]byte, error) { return hex.DecodeString(stripSpace(string(b))) },
	"jsonescape": func(b []byte) ([]byte, error) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(string(b)); err != nil {
			return nil, err
		}
		out := buf.Bytes()
		return out[1 : len(out)-2], nil
	},
	"jsonunescape": func(b []byte) ([]byte, error) {
		var out struct{ Input string }
		if err := json.Unmarshal([]byte(`{"input":"`+string(b)+`"}`), &out); err != nil {
			return nil, err
		}
		return []byte(out.Input), nil
	},
	"lower":  func(b []byte) ([]byte, error) { return []byte(strings.ToLower(string(b))), nil },
	"upper":  func(b []byte) ([]byte, error) { return []byte(strings.ToUpper(string(b))), nil },
	"md5":    func(b []byte) ([]byte, error) { s := md5.Sum(b); return []byte(hex.EncodeToString(s[:])), nil },
	"sha1":   func(b []byte) ([]byte, error) { s := sha1.Sum(b); return []byte(hex.EncodeToString(s[:])), nil },
	"sha224": func(b []byte) ([]byte, error) { s := sha256.Sum224(b); return []byte(hex.EncodeToString(s[:])), nil },
	"sha256": func(b []byte) ([]byte, error) { s := sha256.Sum256(b); return []byte(hex.EncodeToString(s[:])), nil },
	"sha384": func(b []byte) ([]byte, error) { s := sha512.Sum384(b); return []byte(hex.EncodeToString(s[:])), nil },
	"sha512": func(b []byte) ([]byte, error) { s := sha512.Sum512(b); return []byte(hex.EncodeToString(s[:])), nil },
	"unicodeencodeall": func(b []byte) ([]byte, error) {
		var out bytes.Buffer
		for _, r := range string(b) {
			fmt.Fprintf(&out, "\\u%04x", int64(r))
		}
		return out.Bytes(), nil
	},
	"unicodedecode": func(b []byte) ([]byte, error) { return unicodeDecode(b), nil },
	"urlencode":     func(b []byte) ([]byte, error) { return []byte(url.QueryEscape(string(b))), nil },
	"urldecode": func(b []byte) ([]byte, error) {
		s, err := url.QueryUnescape(string(b))
		return []byte(s), err
	},
	"urlencodeall": func(b []byte) ([]byte, error) {
		var out bytes.Buffer
		for _, c := range b {
			out.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
		return out.Bytes(), nil
	},
	"utf16":   func(b []byte) ([]byte, error) { return utf16Bytes(b, binary.LittleEndian), nil },
	"utf16be": func(b []byte) ([]byte, error) { return utf16Bytes(b, binary.BigEndian), nil },
	"xmlescape": func(b []byte) ([]byte, error) {
		var buf bytes.Buffer
		if err := xml.EscapeText(&buf, b); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	},
	"xmlunescape": func(b []byte) ([]byte, error) {
		var out struct {
			Input string `xml:"input"`
		}
		if err := xml.Unmarshal([]byte("<xml><input>"+string(b)+"</input></xml>"), &out); err != nil {
			return nil, err
		}
		return []byte(out.Input), nil
	},
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func utf16Bytes(b []byte, order binary.ByteOrder) []byte {
	var out bytes.Buffer
	for _, u := range utf16.Encode([]rune(string(b))) {
		var two [2]byte
		order.PutUint16(two[:], u)
		out.Write(two[:])
	}
	return out.Bytes()
}

// unicodeDecode turns \uXXXX escapes (surrogate pairs too) into text and
// leaves the rest as it is.
func unicodeDecode(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); {
		if b[i] == '\\' && i+5 < len(b)+0 && b[i+1] == 'u' {
			if n, err := strconv.ParseUint(string(b[i+2:i+6]), 16, 32); err == nil {
				r := rune(n)
				used := 6
				if utf16.IsSurrogate(r) && i+11 < len(b)+0 && b[i+6] == '\\' && b[i+7] == 'u' {
					if m, err := strconv.ParseUint(string(b[i+8:i+12]), 16, 32); err == nil {
						if d := utf16.DecodeRune(r, rune(m)); d != unicode.ReplacementChar {
							r, used = d, 12
						}
					}
				}
				out = utf8.AppendRune(out, r)
				i += used
				continue
			}
		}
		out = append(out, b[i])
		i++
	}
	return out
}

// Chain is the encoders of one keyword, applied in order.
type Chain []func([]byte) ([]byte, error)

// ParseChain reads "urlencode b64encode": names separated by spaces. A name
// ending in .tmpl is a file whose text has #PAYLOAD# replaced by the word.
func ParseChain(spec string) (Chain, error) {
	var c Chain
	for _, name := range strings.Fields(spec) {
		if strings.HasSuffix(name, ".tmpl") {
			text, err := os.ReadFile(name)
			if err != nil {
				return nil, fmt.Errorf("encoder %s: %v", name, err)
			}
			c = append(c, func(b []byte) ([]byte, error) {
				return bytes.ReplaceAll(text, []byte("#PAYLOAD#"), b), nil
			})
			continue
		}
		e, ok := encoders[name]
		if !ok {
			return nil, fmt.Errorf("encoder %q is not one of %s", name, strings.Join(EncoderNames(), ", "))
		}
		c = append(c, e)
	}
	return c, nil
}

// EncoderNames lists what -enc takes (a *.tmpl file too).
func EncoderNames() []string {
	var names []string
	for n := range encoders {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Apply runs the chain over word.
func (c Chain) Apply(word string) (string, error) {
	b := []byte(word)
	for _, e := range c {
		var err error
		if b, err = e(b); err != nil {
			return "", err
		}
	}
	return string(b), nil
}
