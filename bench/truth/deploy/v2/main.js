const api = "/api";
function order(id) { return fetch(`${api}/orders/${id}`, { method: "GET" }); }
function cancelOrder(id) { return fetch(`${api}/orders/${id}`, { method: "DELETE" }); }
function exportData(userId, format) {
  return fetch("/api/v2/export", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ userId: userId, format: format }) });
}
function saveProfile(name, email, role) {
  return fetch("/api/profile", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: name, email: email, role: role }) });
}
