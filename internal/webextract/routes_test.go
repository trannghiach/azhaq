package webextract

import (
	"strings"
	"testing"
)

func routeMap(rs []ClientRoute) map[string]string {
	out := map[string]string{}
	for _, r := range rs {
		out[r.Path] = r.Guard
	}
	return out
}

// Angular's router as an esbuild production build leaves it (Juice
// Shop's main.js): template literals, guards by minified names, a lazy
// view, children joined to their parent and guarded by it.
func TestClientRoutesAngular(t *testing.T) {
	js := "var Hw=[{path:`administration`,component:Su,canActivate:[cs]},{path:`accounting`,component:Vg,canActivate:[ds]}," +
		"{path:`about`,loadComponent:()=>L$1(null,null,function*(){return yield mN()})}," +
		"{path:`address`,canActivate:[Xe],children:[{path:`select`,component:Og},{path:`edit/:addressId`,component:Vc}]}," +
		"{path:`order-completion/:id`,component:Oc},{path:``,redirectTo:`search`,pathMatch:`full`},{path:`**`,component:Nf}];" +
		"var cfg={path:`/`,expires:new Date,secure:!0};" + // a cookie's options
		"Ro.forRoot(Hw,{useHash:!0});"
	rs := ClientRoutes(js)
	got := routeMap(rs)
	want := map[string]string{
		"/administration":           "canActivate",
		"/accounting":               "canActivate",
		"/about":                    "",
		"/address":                  "canActivate",
		"/address/select":           "canActivate",
		"/address/edit/{addressId}": "canActivate",
		"/order-completion/{id}":    "",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, g := range want {
		if gg, ok := got[p]; !ok || gg != g {
			t.Errorf("%s: got %q, %v", p, gg, ok)
		}
	}
	for _, r := range rs {
		if r.Path == "/administration" && js[r.Start:r.End] != "`administration`" {
			t.Errorf("where: %q", js[r.Start:r.End])
		}
	}
	if !HashRouting(js) {
		t.Error("useHash not seen")
	}
}

// Source from a map: the guard has its name.
func TestClientRoutesAngularSource(t *testing.T) {
	ts := `const routes: Routes = [
  { path: 'admin', loadChildren: () => import('./admin/admin.module').then(m => m.AdminModule), canLoad: [AdminGuard] },
  { path: 'login', component: LoginComponent },
  { path: 'settings', component: SettingsComponent, canActivate: [] },
];
@NgModule({ imports: [RouterModule.forRoot(routes)] })`
	got := routeMap(ClientRoutes(ts))
	if got["/admin"] != "canLoad AdminGuard" || got["/login"] != "" || got["/settings"] != "" || len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	if HashRouting(ts) {
		t.Error("no hash routing here")
	}
}

// React Router as the automatic JSX runtime compiles it, and its data
// router.
func TestClientRoutesReact(t *testing.T) {
	js := `(0,o.jsx)(Ie,{children:[(0,o.jsx)(Me,{path:"/",element:(0,o.jsx)(Home,{})}),` +
		`(0,o.jsx)(Me,{path:"/admin/*",element:(0,o.jsx)(RequireAuth,{children:(0,o.jsx)(Admin,{})})}),` +
		`(0,o.jsx)(Me,{path:"/users/:userId",element:(0,o.jsx)(UserPage,{})}),(0,o.jsx)(Me,{path:"*",element:(0,o.jsx)(NotFound,{})})]});` +
		`const router=(0,r.createBrowserRouter)([{path:"/app",element:(0,o.jsx)(Layout,{}),children:[{index:!0,element:(0,o.jsx)(Dash,{})},` +
		`{path:"settings/:tab",lazy:()=>import("./settings-1a.js")},{path:"billing",element:(0,o.jsx)(ProtectedRoute,{children:(0,o.jsx)(Billing,{})})}]}]);`
	got := routeMap(ClientRoutes(js))
	want := map[string]string{
		"/admin":              "RequireAuth",
		"/users/{userId}":     "",
		"/app":                "",
		"/app/settings/{tab}": "",
		"/app/billing":        "ProtectedRoute",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, g := range want {
		if gg, ok := got[p]; !ok || gg != g {
			t.Errorf("%s: got %q, %v", p, gg, ok)
		}
	}
	if HashRouting(js) {
		t.Error("a browser router is not hash routing")
	}
}

// JSX as written, from a source map: <Route> nested, a wrapper named for
// what it guards, and a HashRouter.
func TestClientRoutesJSX(t *testing.T) {
	src := `export default function App() {
  return (
    <HashRouter>
      <Switch>
        <Route exact path="/" component={Home} />
        <PrivateRoute path="/admin" component={Admin} />
        <Route path="/shop" element={<Layout />}>
          <Route path="cart" element={<RequireAuth><Cart /></RequireAuth>} />
          <Route path={"item/:sku"} element={<Item />} />
        </Route>
      </Switch>
    </HashRouter>
  );
}`
	got := routeMap(ClientRoutes(src))
	want := map[string]string{
		"/admin":           "PrivateRoute",
		"/shop":            "",
		"/shop/cart":       "RequireAuth",
		"/shop/item/{sku}": "",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, g := range want {
		if gg, ok := got[p]; !ok || gg != g {
			t.Errorf("%s: got %q, %v", p, gg, ok)
		}
	}
	if !HashRouting(src) {
		t.Error("HashRouter not seen")
	}
}

// Vue Router: guards in meta, hash history, its catch-all left out.
func TestClientRoutesVue(t *testing.T) {
	js := `const Ft=Co({history:Ao(),routes:[{path:"/",name:"home",component:Ho},{path:"/admin",name:"admin",` +
		`component:()=>Kt(()=>import("./Admin-4f1.js"),__vite__mapDeps([0,1])),meta:{requiresAuth:!0,roles:["admin"]}},` +
		`{path:"/about",component:Ab,meta:{title:"About",requiresAuth:!1}},{path:"/user/:id",component:Us,beforeEnter:Gd},` +
		`{path:"/:pathMatch(.*)*",component:Nf}]});function Ao(e){return createWebHashHistory(e)}`
	got := routeMap(ClientRoutes(js))
	want := map[string]string{"/admin": "meta.requiresAuth", "/about": "", "/user/{id}": "beforeEnter"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, g := range want {
		if gg, ok := got[p]; !ok || gg != g {
			t.Errorf("%s: got %q, %v", p, gg, ok)
		}
	}
	if !HashRouting(js) {
		t.Error("createWebHashHistory not seen")
	}
	// The library's own definition is not the app's choice.
	if HashRouting(`function createWebHashHistory(base){return createWebHistory(base)}`) {
		t.Error("a library definition is not hash routing")
	}
}

// Objects with a path that draw nothing are not routes: a socket's or a
// cookie's options, an SVG path, an API description.
func TestClientRoutesNotRoutes(t *testing.T) {
	js := `io(u,{path:"/socket.io",transports:["websocket"]});document.cookie=x({path:"/",expires:1});` +
		`d.append("path").attr({path:"M0 0L10 10",children:[]});var api=[{path:"/api/users",method:"GET",handler:h}];` +
		`var tree={path:"src/app",children:"x y"};`
	if rs := ClientRoutes(js); len(rs) != 0 {
		t.Fatalf("got %+v", rs)
	}
}

func TestJoinRoute(t *testing.T) {
	for _, c := range []struct{ parent, p, want string }{
		{"/", "admin", "/admin"},
		{"/admin", "users/:id", "/admin/users/{id}"},
		{"/admin", "/abs", "/abs"},
		{"/", "post/:slug(\\d+)", "/post/{slug}"},
		{"/", "docs/[...slug]", "/docs/{slug}"},
		{"/", "files/*", "/files"},
	} {
		got, _, ok := joinRoute(c.parent, c.p)
		if !ok || got != c.want {
			t.Errorf("%s + %s: %q %v", c.parent, c.p, got, ok)
		}
	}
	if _, _, ok := joinRoute("/", "a b"); ok {
		t.Error("a space is no route")
	}
	if !strings.HasPrefix(dynamicSegment("[[...slug]]"), "{slug") {
		t.Error("optional catch-all")
	}
}

// React Router's library calls createHashHistory inside its HashRouter:
// an app that uses BrowserRouter does not route by the hash for it. A
// development build names the app's choice.
func TestHashRoutingReact(t *testing.T) {
	lib := `function HashRouter({basename,children,window}){let historyRef=React.useRef();if(historyRef.current==null){historyRef.current=createHashHistory({window,v5Compat:true})}}`
	if HashRouting(lib) {
		t.Error("the library's HashRouter")
	}
	dev := `(0,react_jsx_dev_runtime.jsxDEV)(react_router_dom__WEBPACK_IMPORTED_MODULE_2__.HashRouter, {children:(0,r.jsxDEV)(App,{})})`
	if !HashRouting(dev) {
		t.Error("a development build's HashRouter")
	}
}
