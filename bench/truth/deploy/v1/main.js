const api = "/api";
function order(id) { return fetch(`${api}/orders/${id}`, { method: "GET" }); }
function legacy() { return fetch("/api/legacy/report"); }
function saveProfile(name, email) {
  return fetch("/api/profile", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: name, email: email }) });
}
