package scopefile

import (
	"reflect"
	"strings"
	"testing"
)

func TestHackerOneCSV(t *testing.T) {
	csv := `identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at
*.example.com,WILDCARD,,true,true,,,,critical,,2024-01-01,2024-01-01
https://app.example.org/login,URL,,true,true,,,,critical,,2024-01-01,2024-01-01
"api.example.net,beta.example.net",URL,,true,true,,,,high,,2024-01-01,2024-01-01
com.example.android,GOOGLE_PLAY_APP_ID,,true,true,,,,high,,2024-01-01,2024-01-01
blog.example.com,URL,third party,false,false,,,,none,,2024-01-01,2024-01-01
10.20.0.0/16,CIDR,,true,true,,,,high,,2024-01-01,2024-01-01
`
	s, err := Parse([]byte(csv), "")
	if err != nil {
		t.Fatal(err)
	}
	want := Scope{
		Allow:   []string{"*.example.com", "10.20.0.0/16", "=api.example.net", "=app.example.org", "=beta.example.net"},
		Deny:    []string{"=blog.example.com"},
		Domains: []string{"example.com"},
		Targets: []string{"api.example.net", "beta.example.net", "https://app.example.org/login"},
		Skipped: []string{"com.example.android (GOOGLE_PLAY_APP_ID)"},
	}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("got  %+v\nwant %+v", s, want)
	}
}

func TestProgramLists(t *testing.T) {
	data := `[
 {"handle":"acme","name":"Acme","url":"https://hackerone.com/acme","targets":{"in_scope":[{"asset_identifier":"*.acme.com","asset_type":"WILDCARD","eligible_for_submission":true},{"asset_identifier":"*.acme.*","asset_type":"WILDCARD","eligible_for_submission":true}],"out_of_scope":[{"asset_identifier":"status.acme.com","asset_type":"URL"}]}},
 {"name":"Globex","url":"https://bugcrowd.com/globex","targets":{"in_scope":[{"type":"website","target":"https://shop.globex.io/"},{"type":"api","target":"api.globex.io"}],"out_of_scope":[]}},
 {"handle":"initech","company_handle":"initech","name":"Initech","url":"https://app.intigriti.com/programs/initech/initech","targets":{"in_scope":[{"type":"url","endpoint":"*.initech.eu"},{"type":"url","endpoint":"all"}],"out_of_scope":[]}}
]`
	s, err := Parse([]byte(data), "acme")
	if err != nil || strings.Join(s.Allow, " ") != "*.acme.com" || strings.Join(s.Deny, " ") != "=status.acme.com" || len(s.Skipped) != 1 {
		t.Errorf("acme: %+v %v", s, err)
	}
	if s, _ = Parse([]byte(data), "globex"); strings.Join(s.Targets, " ") != "api.globex.io https://shop.globex.io/" {
		t.Errorf("globex by name: %+v", s)
	}
	if s, _ = Parse([]byte(data), "initech"); strings.Join(s.Domains, " ") != "initech.eu" {
		t.Errorf("intigriti endpoint: %+v", s)
	}
	if _, err := Parse([]byte(data), ""); err == nil {
		t.Error("a list of several programs needs -program")
	}
}

func TestBurpAndLines(t *testing.T) {
	burp := `{"target":{"scope":{"advanced_mode":true,"include":[{"enabled":true,"host":"^.*\\.example\\.com$","protocol":"any"},{"enabled":true,"host":"^api\\.example\\.org$"}],"exclude":[{"enabled":true,"host":"^admin\\.example\\.com$"}]}}}`
	s, err := Parse([]byte(burp), "")
	if err != nil || strings.Join(s.Allow, " ") != "*.example.com =api.example.org" || strings.Join(s.Deny, " ") != "=admin.example.com" {
		t.Errorf("burp: %+v %v", s, err)
	}
	s, err = Parse([]byte("# scope\n*.example.com\napp.example.org:8443\n!legacy.example.com\n192.0.2.10\n"), "")
	if err != nil || strings.Join(s.Allow, " ") != "*.example.com 192.0.2.10 =app.example.org" || strings.Join(s.Targets, " ") != "192.0.2.10 app.example.org:8443" {
		t.Errorf("lines: %+v %v", s, err)
	}
}

func TestFreeTextEntryIsOneSkip(t *testing.T) {
	var b builder
	b.add("Any host verified to be owned by Tesla, such as shop.tesla.com", "other_web", true)
	b.add("energysupport.tesla.com (report it to bugbounty.zoho.com)", "website", false)
	sc := b.scope()
	if len(sc.Skipped) != 2 || !strings.HasPrefix(sc.Skipped[0], "Any host verified") {
		t.Fatalf("skipped %q", sc.Skipped)
	}
	if len(sc.Targets) != 0 || len(sc.Allow) != 0 {
		t.Fatalf("a host named in a sentence widened the scope: %v %v", sc.Targets, sc.Allow)
	}
	if strings.Join(sc.Deny, ",") != "=bugbounty.zoho.com,=energysupport.tesla.com" {
		t.Fatalf("hosts named in an exclusion narrow it: %v", sc.Deny)
	}
}
