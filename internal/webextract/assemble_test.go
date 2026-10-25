package webextract

import (
	"reflect"
	"testing"
)

func TestAssembled(t *testing.T) {
	// Shaped like crAPI's bundle: prefixes and a table of paths, joined
	// where the request is made.
	script := `og="identity/",ig="workshop/",ag="chatbot/",sg={LOGIN:"api/auth/login",GET_VIDEO:"api/v2/user/videos/<videoId>",UNUSED:"api/never/joined",TITLE:"Sign in"};
	function*Mg(e){const t=og+sg.LOGIN;yield fetch(t,{method:"POST"})}
	const u=(og+sg.GET_VIDEO).replace("<videoId>",e.id);
	const s=ag+"genai/state";
	const w=` + "`${ig}api/shop/products`" + `;
	const x=` + "`${og}${sg.LOGIN}`" + `;
	var e="a",e="b";const y=e+sg.LOGIN;
	const z=og+sg.TITLE;
	const px=n+"px",cls=k+"/";k="col";`
	got := Assembled(script)
	want := []string{
		"chatbot/genai/state",
		"identity/api/auth/login",
		"identity/api/v2/user/videos/{videoId}",
		"workshop/api/shop/products",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestAssembledNeedsOneBinding(t *testing.T) {
	// Two objects bound to the same minified name: the join is ambiguous.
	script := `a="v1/";o={X:"users"};function f(){o={X:"orders"}};g(a+o.X)`
	if got := Assembled(script); len(got) != 0 {
		t.Errorf("ambiguous join resolved: %q", got)
	}
}

func TestGraphQLOps(t *testing.T) {
	script := `const Q=gql` + "`" + `query GetUser($id: ID!) { user(id: $id) { email } }` + "`" + `;
	var d={kind:"Document",definitions:[{kind:"OperationDefinition",operation:"mutation",name:{kind:"Name",value:"Login"},variableDefinitions:[]}]};
	function query(a){return a}; query (x); var subscription = 1;`
	got := GraphQLOps(script)
	if !reflect.DeepEqual(got, []string{"query GetUser", "mutation Login"}) {
		t.Errorf("ops %q", got)
	}
}
