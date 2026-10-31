"use strict";
// The gallery page: reads the JSON API of the server it came from and
// nothing else. Every value from a workspace is set as text, never as HTML.

const $ = (s) => document.querySelector(s);
const view = $("#view");
const qbox = $("#q");
let seq = 0; // the newest render; an older answer is dropped
let lastIDs = []; // pages of the last list, for the arrows in a detail view

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "text") e.textContent = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

async function api(path, params) {
  const u = new URL(path, location.origin);
  if (params) for (const [k, v] of params) u.searchParams.append(k, v);
  const r = await fetch(u);
  if (!r.ok) {
    let m = r.statusText;
    try { m = (await r.json()).error || m; } catch (_) {}
    throw new Error(m);
  }
  return r.json();
}

function route() {
  const raw = location.hash.replace(/^#/, "") || "/";
  const i = raw.indexOf("?");
  const path = i < 0 ? raw : raw.slice(0, i);
  return { path, params: new URLSearchParams(i < 0 ? "" : raw.slice(i + 1)) };
}

function go(path, params) {
  const s = params ? params.toString() : "";
  location.hash = "#" + path + (s ? "?" + s : "");
}

function setParam(params, key, val) {
  const p = new URLSearchParams(params);
  p.delete(key);
  if (val !== "" && val != null) p.set(key, val);
  p.delete("offset");
  return p;
}

function toggleParam(params, key, val) {
  const p = new URLSearchParams(params);
  const all = p.getAll(key);
  p.delete(key);
  if (all.includes(val)) all.filter((x) => x !== val).forEach((x) => p.append(key, x));
  else [...all, val].forEach((x) => p.append(key, x));
  p.delete("offset");
  return p;
}

function statusClass(code) {
  return "s" + (code ? String(code)[0] : "0");
}

function fmtTime(t) {
  const d = new Date(t);
  return isNaN(d) ? "" : d.toLocaleString();
}

function nav(on) {
  for (const id of ["grid", "groups", "failed", "stats"]) $("#nav-" + id).classList.toggle("on", id === on);
}

async function warnings() {
  try {
    const st = await api("/api/stats");
    const box = $("#warn");
    box.replaceChildren(...st.warnings.map((w) => h("p", { class: "w" + (w.partial ? " partial" : "") }, (w.workspace ? w.workspace + ": " : "") + w.message)));
    const b = st.body_text;
    if (st.not_taken) box.append(h("p", { class: "w" }, `${st.not_taken} pages gave no picture: see Not taken.`));
    if (b.kept < st.pages) box.append(h("p", { class: "w" }, `Page text is kept for ${b.kept} of ${st.pages} pages (azhaq run -shot-html keeps it); a body: or free-text search reads only those.`));
  } catch (_) {}
}

// ---- the grid of pages

function chip(label, onclick) {
  return h("span", { class: "chip", onclick, title: "remove" }, label);
}

function facet(list, key, params, opts = {}) {
  const on = params.getAll(key);
  return list.map((c) =>
    h("div", { class: "facet" + (on.includes(c.value) ? " on" : ""), onclick: () => go("/", opts.single ? setParam(params, key, on.includes(c.value) ? "" : c.value) : toggleParam(params, key, c.value)) },
      h("span", { title: c.value }, c.value), h("span", {}, c.count)));
}

async function renderGrid(params) {
  nav("grid");
  const me = ++seq;
  const limit = parseInt(params.get("limit") || "48", 10);
  const offset = parseInt(params.get("offset") || "0", 10);
  const q = new URLSearchParams(params);
  q.set("limit", limit);
  q.set("offset", offset);
  let list, fc;
  try {
    [list, fc] = await Promise.all([api("/api/shots", q), api("/api/facets", q)]);
  } catch (e) {
    view.replaceChildren(h("div", { class: "empty err" }, e.message));
    return;
  }
  if (me !== seq) return;
  lastIDs = list.shots.map((s) => s.id);
  if (document.activeElement !== qbox) qbox.value = params.get("q") || "";

  const side = h("aside", {},
    h("h3", {}, "Host"),
    h("input", { type: "search", placeholder: "host contains…", value: params.get("host") || "", onchange: (e) => go("/", setParam(params, "host", e.target.value.trim())) }),
    h("h3", {}, "Title"),
    h("input", { type: "search", placeholder: "title contains…", value: params.get("title") || "", onchange: (e) => go("/", setParam(params, "title", e.target.value.trim())) }),
    h("h3", {}, "Status"), facet(fc.status, "status", params),
    h("h3", {}, "Technology"), facet(fc.technologies, "tech", params),
    h("h3", {}, "Complete"),
    fc.partial.map((c) => h("div", { class: "facet" + (params.get("partial") === c.value ? " on" : ""), onclick: () => go("/", setParam(params, "partial", params.get("partial") === c.value ? "" : c.value)) },
      h("span", {}, c.value === "yes" ? "partial" : "complete"), h("span", {}, c.count))),
    fc.workspaces ? [h("h3", {}, "Workspace"), facet(fc.workspaces, "workspace", params, { single: true })] : null,
    h("h3", {}, "Most common hosts"), facet(fc.hosts.slice(0, 12), "host", params, { single: true }));

  const chips = [];
  for (const k of ["status", "tech"]) for (const v of params.getAll(k)) chips.push(chip(k + ": " + v, () => go("/", toggleParam(params, k, v))));
  for (const k of ["host", "title", "partial", "workspace", "group"]) if (params.get(k)) chips.push(chip(k + ": " + params.get(k), () => go("/", setParam(params, k, ""))));
  if (params.get("collapse") === "1") chips.push(chip("one per look-alike group", () => go("/", setParam(params, "collapse", ""))));

  const asTable = params.get("view") === "table";
  const sel = (name, opts, cur, fn) => h("select", { onchange: (e) => fn(e.target.value) }, opts.map(([v, l]) => h("option", { value: v, selected: v === cur }, l)));
  const bar = h("div", { class: "bar" },
    h("strong", {}, `${list.total.toLocaleString()} ${params.get("collapse") === "1" ? "groups" : "pages"}`),
    h("span", {}, `${list.took_ms.toFixed(1)} ms`),
    h("span", { class: "sp" }),
    h("label", {}, "Sort ", sel("sort", [["url", "URL"], ["host", "Host"], ["title", "Title"], ["status", "Status"], ["group", "Look-alike group"], ["time", "Newest"]], params.get("sort") || "url", (v) => go("/", setParam(params, "sort", v)))),
    h("label", {}, h("input", { type: "checkbox", checked: params.get("order") === "desc", onchange: (e) => go("/", setParam(params, "order", e.target.checked ? "desc" : "")) }), "reverse"),
    h("label", {}, h("input", { type: "checkbox", checked: params.get("collapse") === "1", onchange: (e) => go("/", setParam(params, "collapse", e.target.checked ? "1" : "")) }), "one per look-alike group"),
    h("label", {}, "View ", sel("view", [["grid", "Grid"], ["table", "Table"]], asTable ? "table" : "grid", (v) => go("/", setParam(params, "view", v === "table" ? "table" : "")))),
    h("label", {}, "Per page ", sel("limit", [24, 48, 96, 200].map((n) => [String(n), String(n)]), String(limit), (v) => go("/", setParam(params, "limit", v)))));

  const grid = !list.shots.length ? h("div", { class: "empty" }, "No page matches.")
    : asTable ? rowsTable(list.shots, params)
    : h("div", { class: "grid" }, list.shots.map((s) => card(s, params)));

  const pages = Math.max(Math.ceil(list.total / limit), 1), page = Math.floor(offset / limit) + 1;
  const at = (n) => { const p = new URLSearchParams(params); p.set("offset", String((n - 1) * limit)); go("/", p); window.scrollTo(0, 0); };
  const pager = h("div", { class: "pager" },
    h("button", { disabled: page <= 1, onclick: () => at(1) }, "« first"),
    h("button", { disabled: page <= 1, onclick: () => at(page - 1) }, "‹ prev"),
    h("span", {}, `page ${page} of ${pages}`),
    h("button", { disabled: page >= pages, onclick: () => at(page + 1) }, "next ›"),
    h("button", { disabled: page >= pages, onclick: () => at(pages) }, "last »"));

  view.replaceChildren(h("div", { class: "layout" }, side, h("div", {}, bar, chips.length ? h("div", { class: "chips" }, chips) : null, grid, pager)));
}

// partialLabel is "partial", and in brackets what the picture lacks.
function partialLabel(s) {
  return s.partial_why ? "partial (" + s.partial_why + ")" : "partial";
}

function rowsTable(shots, params) {
  const link = (s) => "#/shot/" + encodeURIComponent(s.id) + "?" + new URLSearchParams([...params].filter(([k]) => k !== "offset")).toString();
  return h("table", {}, h("thead", {}, h("tr", {}, ["", "Status", "Title", "URL", "Technologies", "Group", "Taken"].map((x) => h("th", {}, x)))),
    h("tbody", {}, shots.map((s) => h("tr", {},
      h("td", {}, h("a", { href: link(s) }, h("img", { src: "/img/" + encodeURIComponent(s.id) + "/thumb", loading: "lazy", alt: "", width: "96" }))),
      h("td", {}, h("span", { class: "badge inline " + statusClass(s.status) }, s.status || "—"), s.partial ? h("span", { class: "tag warn", title: s.partial_why || "" }, partialLabel(s)) : null),
      h("td", {}, h("a", { href: link(s) }, s.title || "(no title)")),
      h("td", { class: "m" }, s.url),
      h("td", {}, (s.technologies || []).join(", ")),
      h("td", {}, s.group_size > 1 ? h("a", { href: "#/?group=" + s.group }, "×" + s.group_size) : ""),
      h("td", {}, fmtTime(s.taken_at))))));
}

function card(s, params) {
  const link = "#/shot/" + encodeURIComponent(s.id) + (params ? "?" + new URLSearchParams([...params].filter(([k]) => k !== "offset")).toString() : "");
  const img = h("img", { src: "/img/" + encodeURIComponent(s.id) + "/thumb", loading: "lazy", alt: s.title || s.url, decoding: "async" });
  const thumb = h("a", { class: "thumb", href: link }, img,
    h("span", { class: "badge l " + statusClass(s.status) }, s.status || "—"),
    s.group_size > 1 ? h("span", { class: "badge r", title: "look-alike group " + s.group + ": show its pages", onclick: (e) => { e.preventDefault(); const p = new URLSearchParams(params); p.delete("collapse"); p.delete("offset"); p.set("group", s.group); go("/", p); } },
      "×" + (s.group_matches && s.group_matches !== s.group_size ? s.group_matches + "/" : "") + s.group_size) : null);
  img.addEventListener("error", () => { img.remove(); thumb.append(h("span", { class: "gone" }, s.has_file ? "no picture" : "picture file missing")); });
  return h("div", { class: "card" }, thumb,
    h("div", { class: "meta" },
      h("div", { class: "t", title: s.title }, s.title || "(no title)"),
      h("div", { class: "u", title: s.url }, s.url),
      h("div", { class: "tags" }, s.partial ? h("span", { class: "tag warn", title: s.partial_why || "taken before the page finished loading" }, partialLabel(s)) : null,
        s.workspace ? h("span", { class: "tag" }, s.workspace) : null,
        (s.technologies || []).slice(0, 6).map((t) => h("span", { class: "tag" }, t)),
        (s.technologies || []).length > 6 ? h("span", { class: "tag" }, "+" + (s.technologies.length - 6)) : null)));
}

// ---- the look-alike groups

async function renderGroups() {
  nav("groups");
  const me = ++seq;
  let r;
  try { r = await api("/api/groups", new URLSearchParams({ min: "2", limit: "500" })); } catch (e) { view.replaceChildren(h("div", { class: "empty err" }, e.message)); return; }
  if (me !== seq) return;
  view.replaceChildren(h("div", { class: "detail" },
    h("div", { class: "dhead" }, h("h2", {}, "Look-alike groups"), h("span", { class: "dim" }, `${r.groups.length} groups of 2 or more pages, among ${r.total} in all; pages whose pictures differ by at most 10 of 64 hash bits`)),
    r.groups.length ? h("div", { class: "grid" }, r.groups.map((g) =>
      h("div", { class: "card" },
        h("a", { class: "thumb", href: "#/?group=" + g.group }, h("img", { src: "/img/" + encodeURIComponent(g.sample) + "/thumb", loading: "lazy", alt: "" }), h("span", { class: "badge r" }, "×" + g.size)),
        h("div", { class: "meta" }, h("div", { class: "t", title: g.title }, g.title || "(no title)"), h("div", { class: "u" }, `${g.size} pages on ${g.hosts} host${g.hosts === 1 ? "" : "s"}`))))) : h("div", { class: "empty" }, "No two pages look alike.")));
}

// ---- pages that gave no picture

async function renderFailed(params) {
  nav("failed");
  const me = ++seq;
  const limit = 100, offset = parseInt(params.get("offset") || "0", 10);
  const q = new URLSearchParams(params);
  q.set("limit", limit);
  q.set("offset", offset);
  let r;
  try { r = await api("/api/failed", q); } catch (e) { view.replaceChildren(h("div", { class: "empty err" }, e.message)); return; }
  if (me !== seq) return;
  const at = (n) => { const p = new URLSearchParams(params); p.set("offset", String(n)); go("/failed", p); };
  view.replaceChildren(h("div", { class: "detail" },
    h("div", { class: "dhead" }, h("h2", {}, "Pages that gave no picture"), h("span", { class: "dim" }, `${r.total} listed; an error is a page that did not load, a note a page left out on purpose (-shot-codes)`),
      h("select", { onchange: (e) => go("/failed", setParam(params, "kind", e.target.value)) }, [["", "all"], ["error", "errors"], ["note", "notes"]].map(([v, l]) => h("option", { value: v, selected: v === (params.get("kind") || "") }, l))),
      h("input", { type: "search", placeholder: "filter…", value: params.get("q") || "", onchange: (e) => go("/failed", setParam(params, "q", e.target.value.trim())) })),
    r.failed.length ? table(["Kind", "URL", "Workspace", "Reason"], r.failed.map((f) => [f.kind, f.url, f.workspace || "", f.reason])) : h("div", { class: "empty" }, "Nothing."),
    h("div", { class: "pager" }, h("button", { disabled: offset <= 0, onclick: () => at(Math.max(offset - limit, 0)) }, "‹ prev"), h("span", {}, `${r.total ? offset + 1 : 0}–${Math.min(offset + limit, r.total)} of ${r.total}`), h("button", { disabled: offset + limit >= r.total, onclick: () => at(offset + limit) }, "next ›"))));
}

// ---- statistics

async function renderStats() {
  nav("stats");
  const me = ++seq;
  let st;
  try { st = await api("/api/stats"); } catch (e) { view.replaceChildren(h("div", { class: "empty err" }, e.message)); return; }
  if (me !== seq) return;
  const max = Math.max(1, ...Object.values(st.statuses));
  const bars = (rows, link) => h("div", { class: "bars" }, rows.map(([k, v, to]) => h("div", { class: "row" }, h("a", { href: to || "#/" }, k), bar(Math.max(v / max * 100, 1)), h("span", {}, v))));
  const codes = Object.entries(st.statuses).sort(([a], [b]) => a.localeCompare(b));
  view.replaceChildren(h("div", { class: "detail" },
    h("div", { class: "dhead" }, h("h2", {}, "Statistics")),
    h("div", { class: "box" }, h("h3", {}, "Workspace"), h("dl", { class: "kv" },
      h("dt", {}, "pages"), h("dd", {}, st.pages), h("dt", {}, "look-alike groups"), h("dd", {}, `${st.groups} (${st.pages_in_groups} pages in a group of 2 or more)`),
      h("dt", {}, "response headers"), h("dd", {}, st.headers), h("dt", {}, "network requests"), h("dd", {}, st.network_requests), h("dt", {}, "console lines"), h("dd", {}, st.console_lines),
      h("dt", {}, "partial"), h("dd", {}, st.partial), h("dt", {}, "pages with no picture"), h("dd", {}, h("a", { href: "#/failed" }, st.not_taken)), h("dt", {}, "picture files missing"), h("dd", {}, st.files_missing),
      h("dt", {}, "page text"), h("dd", {}, `${st.body_text.kept} kept, ${st.body_text.indexed} read into the search${st.body_text.ready ? "" : " (reading)"}`),
      st.workspaces.map((w) => [h("dt", {}, "workspace"), h("dd", {}, `${w.path}: ${w.pages} pages, ${(w.bytes / 1048576).toFixed(1)} MB`)]))),
    h("div", { class: "box" }, h("h3", {}, "Status codes"), bars(codes.map(([k, v]) => [k, v, "#/?status=" + (k === "none" ? "none" : k)]))),
    h("div", { class: "box" }, h("h3", {}, "Technologies"), h("div", { class: "tags" }, st.technologies.map((t) => h("a", { class: "tag", href: "#/?tech=" + encodeURIComponent(t.value) }, `${t.value} ${t.count}`)))),
    st.largest_groups && st.largest_groups.length ? h("div", { class: "box" }, h("h3", {}, "Largest look-alike groups"), st.largest_groups.map((g) => h("div", {}, h("a", { href: "#/?group=" + g.group }, `×${g.size}`), " ", g.title || "(no title)", h("span", { class: "dim" }, ` on ${g.hosts} host${g.hosts === 1 ? "" : "s"}`)))) : null));
}

// ---- one page

// bar is a bar of the given width; the width is set on the element, which
// the page's style policy allows, unlike a style attribute.
function bar(pct) {
  const b = h("div", { class: "b" });
  b.style.width = pct + "%";
  return b;
}

function kv(rows) {
  return h("dl", { class: "kv" }, rows.filter(([, v]) => v !== "" && v != null && v !== 0).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
}

function table(head, rows) {
  return h("table", {}, h("thead", {}, h("tr", {}, head.map((x) => h("th", {}, x)))), h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c, i) => h("td", { class: i === r.length - 1 || head[i] === "URL" ? "m" : "" }, c))))));
}

async function renderShot(id, params) {
  nav("");
  const me = ++seq;
  let d;
  try { d = await api("/api/shots/" + encodeURIComponent(id)); } catch (e) { view.replaceChildren(h("div", { class: "detail" }, h("div", { class: "empty err" }, e.message), h("a", { href: "#/" }, "back"))); return; }
  if (me !== seq) return;
  const rec = d.record || {};
  const idx = lastIDs.indexOf(id);
  const back = "#/" + (params.toString() ? "?" + params : "");
  const step = (n) => { const to = lastIDs[idx + n]; if (to) go("/shot/" + encodeURIComponent(to), params); };
  const full = "/img/" + encodeURIComponent(id) + "/full";
  const isWeb = /^https?:\/\//i.test(d.url);

  const picture = h("div", { class: "pic" }, h("a", { href: full, target: "_blank", rel: "noopener" }, h("img", { src: full, alt: d.title || d.url, onerror: (e) => e.target.replaceWith(h("div", { class: "empty" }, "The picture file is not on disk.")) })));

  const tabs = {
    Headers: () => (rec.headers && rec.headers.length) ? table(["Header", "Value"], rec.headers.map((x) => [x.key, x.value])) : h("div", { class: "dim" }, "No response headers were recorded."),
    TLS: () => rec.tls ? kv([["protocol", rec.tls.protocol], ["key exchange", rec.tls.key_exchange], ["cipher", rec.tls.cipher], ["subject", rec.tls.subject_name], ["issuer", rec.tls.issuer], ["valid from", rec.tls.valid_from], ["valid to", rec.tls.valid_to], ["names", (rec.tls.san_list || []).join(", ")], ["encrypted client hello", rec.tls.encrypted_client_hello ? "yes" : ""]]) : h("div", { class: "dim" }, "No TLS session was recorded (a plain HTTP page, or an older workspace)."),
    Cookies: () => {
      const c = (rec.headers || []).filter((x) => x.key.toLowerCase() === "set-cookie").map((x) => {
        const [nv, ...attrs] = x.value.split(";");
        const i = nv.indexOf("=");
        return [i < 0 ? nv.trim() : nv.slice(0, i).trim(), i < 0 ? "" : nv.slice(i + 1).trim(), attrs.map((a) => a.trim()).join("; ")];
      });
      return c.length ? table(["Name", "Value", "Attributes"], c) : h("div", { class: "dim" }, "The page set no cookies.");
    },
    Network: () => {
      const n = rec.network || [];
      if (!n.length) return h("div", { class: "dim" }, "No requests were recorded.");
      let shown = 200;
      const wrap = h("div", {});
      const draw = () => wrap.replaceChildren(
        table(["Type", "Method", "Status", "Bytes", "ms", "URL"], n.slice(0, shown).map((x) => [x.request_type, x.method || "", x.error ? "error" : (x.status_code || ""), x.bytes || "", x.time_ms ? Math.round(x.time_ms) : "", x.url + (x.error ? "  — " + x.error : "")])),
        n.length > shown ? h("p", {}, h("button", { onclick: () => { shown = n.length; draw(); } }, `show all ${n.length}`)) : null,
        rec.network_more ? h("p", { class: "dim" }, `${rec.network_more} more requests were made past the cap and are not listed.`) : null);
      draw();
      return wrap;
    },
    Console: () => (rec.console && rec.console.length) ? table(["Type", "Message"], rec.console.map((x) => [x.type, x.value])) : h("div", { class: "dim" }, "Nothing was written to the console."),
    "Page text": () => d.body_text ? h("div", {}, h("pre", {}, d.body_text), d.body_cut ? h("p", { class: "dim" }, "Cut here; the whole page is in the file kept beside the picture.") : null) : h("div", { class: "dim" }, "The page's text was not kept (azhaq run -shot-html keeps it)."),
    HTML: () => d.body_html ? h("pre", {}, d.body_html) : h("div", { class: "dim" }, "The page's source was not kept (azhaq run -shot-html keeps it)."),
    Azhaq: () => {
      const box = h("div", {}, h("div", { class: "cmd" }, h("code", {}, d.show_command), h("button", { onclick: (e) => { navigator.clipboard && navigator.clipboard.writeText(d.show_command); e.target.textContent = "copied"; } }, "copy")), h("p", { class: "dim" }, "What the workspace holds of this URL:"));
      api("/api/shots/" + encodeURIComponent(id) + "/show").then((s) => {
        box.append(kv([["type", s.entity.type], ["key", s.entity.key], ["first seen", fmtTime(s.entity.first_seen)], ["last seen", fmtTime(s.entity.last_seen)]]),
          h("h3", { class: "dim" }, `Links (${s.links.length})`), s.links.length ? table(["Relation", "Direction", "Type", "Key"], s.links.map((l) => [l.rel, l.dir, l.type, l.key])) : h("div", { class: "dim" }, "none"),
          h("h3", { class: "dim" }, `Observations (${s.observations.length})`), table(["Collector", "Kind", "At", "Bytes"], s.observations.map((o) => [o.collector, o.kind, fmtTime(o.observed_at), o.payload_bytes])));
      }).catch((e) => box.append(h("div", { class: "err" }, e.message)));
      return box;
    },
  };
  const tabBar = h("div", { class: "tabs" });
  const tabBody = h("div", {});
  const names = Object.keys(tabs);
  const pick = (n) => { [...tabBar.children].forEach((c) => c.classList.toggle("on", c.dataset.n === n)); tabBody.replaceChildren(tabs[n]()); };
  const count = { Headers: (rec.headers || []).length, Cookies: (rec.headers || []).filter((x) => x.key.toLowerCase() === "set-cookie").length, Network: (rec.network || []).length, Console: (rec.console || []).length };
  names.forEach((n) => tabBar.append(h("div", { class: "tab", "data-n": n, onclick: () => pick(n) }, n + (count[n] != null ? " " + count[n] : ""))));

  const side = [
    h("div", { class: "box" }, h("h3", {}, "Page"), kv([
      ["URL", isWeb ? h("a", { href: d.url, target: "_blank", rel: "noopener noreferrer" }, d.url) : d.url],
      ["final URL", d.final_url && d.final_url !== d.url ? d.final_url : ""],
      ["title", d.title], ["status", rec.response_code ? rec.response_code + (rec.response_reason ? " " + rec.response_reason : "") : ""],
      ["protocol", rec.protocol], ["document size", rec.content_length ? rec.content_length + " bytes" : ""],
      ["technologies", (d.technologies || []).join(", ")],
      ["taken", fmtTime(d.taken_at)], ["workspace", d.workspace], ["perceptual hash", d.hash],
      ["look-alike group", d.group_size > 1 ? h("a", { href: "#/?group=" + d.group }, `${d.group} (${d.group_size} pages)`) : ""]])),
    d.partial ? h("div", { class: "box" }, h("h3", {}, "Partial"), h("div", { class: "err" }, rec.note || "Taken before the page finished loading.")) : null,
    d.problem ? h("div", { class: "box err" }, d.problem) : null,
    d.group_members.length ? h("div", { class: "box" }, h("h3", {}, "Looks like"), h("div", { class: "mem" }, d.group_members.map((m) => h("a", { href: "#/shot/" + encodeURIComponent(m.id), title: m.url }, h("img", { src: "/img/" + encodeURIComponent(m.id) + "/thumb", loading: "lazy", alt: "" }), h("span", {}, m.url))))) : null,
  ];

  view.replaceChildren(h("div", { class: "detail" },
    h("div", { class: "dhead" }, h("a", { href: back }, "‹ back"), h("h2", {}, d.title || "(no title)"),
      h("span", { class: "badge inline " + statusClass(d.status) }, d.status || "—"),
      h("span", { class: "sp" }),
      h("button", { disabled: idx <= 0, onclick: () => step(-1) }, "‹ prev"), h("button", { disabled: idx < 0 || idx >= lastIDs.length - 1, onclick: () => step(1) }, "next ›")),
    h("div", { class: "dgrid" }, picture, h("div", {}, side)),
    tabBar, tabBody));
  pick("Headers");
}

// ---- routing

function render() {
  const { path, params } = route();
  if (path === "/groups") return renderGroups();
  if (path === "/stats") return renderStats();
  if (path === "/failed") return renderFailed(params);
  if (path.startsWith("/shot/")) return renderShot(decodeURIComponent(path.slice(6)), params);
  return renderGrid(params);
}

let debounce;
qbox.addEventListener("input", () => {
  clearTimeout(debounce);
  debounce = setTimeout(() => {
    const { path, params } = route();
    go("/", setParam(path === "/" ? params : new URLSearchParams(), "q", qbox.value.trim()));
  }, 250);
});
document.addEventListener("keydown", (e) => {
  const { path, params } = route();
  if (!path.startsWith("/shot/") || /input|select|textarea/i.test(e.target.tagName)) return;
  const id = decodeURIComponent(path.slice(6)), i = lastIDs.indexOf(id);
  if (e.key === "Escape") go("/", params);
  else if (e.key === "ArrowRight" && lastIDs[i + 1]) go("/shot/" + encodeURIComponent(lastIDs[i + 1]), params);
  else if (e.key === "ArrowLeft" && i > 0) go("/shot/" + encodeURIComponent(lastIDs[i - 1]), params);
});
window.addEventListener("hashchange", render);
warnings();
render();
