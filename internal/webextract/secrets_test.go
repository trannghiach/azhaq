package webextract

import (
	"os"
	"strings"
	"testing"
)

func TestSecretsInPlantedScript(t *testing.T) {
	raw, err := os.ReadFile("../../bench/truth/secrets.js")
	if err != nil {
		t.Fatal(err)
	}
	// "@@" keeps secret scanners off the fixture; the values here are
	// split for the same reason.
	got := map[string]string{}
	for _, s := range Secrets(strings.ReplaceAll(string(raw), "@@", "")) {
		got[s.Kind+" "+s.Value] = s.Severity
	}
	for _, want := range []string{
		"aws-access-key-id AKIAIOSFODNN7EXAMPLE", "aws-secret-access-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"google-api-key AIza" + "SyDq2q7Z0v9nV5aYbB1kQ8wL3mN4pR6tUeX", "github-token ghp" + "_Z8xQm2Lr7Vb4Tn9Wc1Ks6Jd3Hf5Gy0Pa2Ue4R",
		"slack-webhook https://hooks.slack.com/services/T0AZHAQ01/B0AZHAQ02" + "/q7X9mK2vL4pR8tW3yZ6aB1cD",
		"stripe-secret-key sk_live" + "_4eC39HqLyjWDarjtT1zdp7dcAZHAQ", "private-key -----BEGIN RSA PRIVATE KEY-----",
		"build-variable https://api.azhaq-bench.example", "generic-secret Xk29fLq0Pz8vRt3Yw6Nb",
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhemhhcS1iZW5jaCJ9.c2lnbmF0dXJlLW5vdC1yZWFs",
		"sendgrid-key SG" + ".bQ7rT2mX9vL4kP8nW3yZ6a.Zx8Qm2Lr7Vb4Tn9Wc1Ks6Jd3Hf5Gy0Pa2Ue4RqTsYuW",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	if got["aws-access-key-id AKIAIOSFODNN7EXAMPLE"] != "high" {
		t.Error("an access key next to its secret is high")
	}
	for k := range got {
		for _, bad := range []string{"YOUR_API_KEY", "auth.token.label", " password"} {
			if len(k) >= len(bad) && k[len(k)-len(bad):] == bad {
				t.Errorf("look-alike reported: %s", k)
			}
		}
	}
}
