// labexpress: deliberately vulnerable AND safe endpoints for ml-dast ground truth.
// LAB ONLY. Published on 127.0.0.1 only through the lab compose file. Never deploy.
// Every route is listed in services-ml/ml-dast/data/dast/ground_truth.json.
"use strict";
const express = require("express");
const escapeHtml = require("escape-html");
const { Pool } = require("pg");
const { exec, execFile } = require("child_process");
const fs = require("fs");
const path = require("path");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const FILES = "/srv/files";
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// Express 4 does not catch rejected async handlers and Node 20 exits on an unhandled rejection
// (an out-of-range id crashed the app during a ZAP scan). Route every handler's rejection to the
// error handler at the bottom, which answers with a generic 500.
for (const m of ["get", "post"]) {
  const orig = app[m].bind(app);
  app[m] = (p, ...handlers) => orig(p, ...handlers.map((h) => (req, res, next) => Promise.resolve(h(req, res, next)).catch(next)));
}

const page = (title, body) => `<!doctype html><html><head><title>${escapeHtml(title)}</title></head><body><h2>${escapeHtml(title)}</h2>${body}<p><a href="/">home</a></p></body></html>`;
const list = (rows) => "<table>" + rows.map((r) => `<tr><td>${escapeHtml(String(r.title))}</td><td>${escapeHtml(String(r.category))}</td></tr>`).join("") + "</table>";

async function init() {
  for (let i = 0; i < 30; i++) {
    try {
      await pool.query(`DROP TABLE IF EXISTS books; DROP TABLE IF EXISTS members;
        CREATE TABLE books (id SERIAL PRIMARY KEY, title TEXT, category TEXT);
        CREATE TABLE members (id SERIAL PRIMARY KEY, email TEXT, name TEXT);
        INSERT INTO books (title, category) VALUES ('Dune','scifi'),('Emma','classic'),('Ubik','scifi'),('Ulysses','classic');
        INSERT INTO members (email, name) VALUES ('ann@lab.test','Ann'),('raj@lab.test','Raj');`);
      break;
    } catch (e) {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  fs.mkdirSync(FILES, { recursive: true });
  fs.writeFileSync(path.join(FILES, "guide.txt"), "lab guide\n");
}

app.get("/", (req, res) => {
  const links = ["/books?category=scifi", "/books-safe?category=scifi", "/book/1", "/book-safe/1", "/hello?name=guest", "/hello-safe?name=guest",
    "/banner?msg=welcome", "/banner-safe?msg=welcome", "/api/echo?q=hi", "/members", "/members-safe", "/lookup", "/lookup-safe",
    "/sort?by=title", "/sort-safe?by=title", "/convert?amount=3", "/dns?host=localhost", "/dns-safe?host=localhost",
    "/file?name=guide.txt", "/file-safe?name=guide.txt", "/v2", "/v3"];
  res.send(page("labexpress", "<ul>" + links.map((l) => `<li><a href="${l}">${l}</a></li>`).join("") + "</ul>"));
});

// ---------- CWE-89 ----------
app.get("/books", async (req, res) => { // VULN CWE-89: string-built, pg error text shown
  try {
    const r = await pool.query("SELECT title, category FROM books WHERE category = '" + (req.query.category || "") + "'");
    res.send(page("books", list(r.rows)));
  } catch (e) {
    res.status(500).send(page("error", `<pre>error: ${escapeHtml(e.message)}</pre>`));
  }
});
app.get("/books-safe", async (req, res) => { // SAFE
  const r = await pool.query("SELECT title, category FROM books WHERE category = $1", [String(req.query.category || "")]);
  res.send(page("books", list(r.rows)));
});
app.get("/book/:id", async (req, res) => { // VULN CWE-89: path parameter, numeric, errors hidden
  try {
    const r = await pool.query("SELECT title, category FROM books WHERE id = " + req.params.id);
    res.send(page("book", r.rows.length ? list(r.rows) : "<p>not found</p>"));
  } catch (e) {
    res.send(page("book", "<p>not found</p>"));
  }
});
app.get("/book-safe/:id", async (req, res) => { // SAFE
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send(page("book", "<p>bad id</p>"));
  const r = await pool.query("SELECT title, category FROM books WHERE id = $1", [id]);
  res.send(page("book", r.rows.length ? list(r.rows) : "<p>not found</p>"));
});
const LOOKUP = '<form method="post"><input name="email"><button>lookup</button></form>';
app.get("/lookup", (req, res) => res.send(page("lookup", LOOKUP)));
app.get("/lookup-safe", (req, res) => res.send(page("lookup", LOOKUP)));
app.post("/lookup", async (req, res) => { // VULN CWE-89: form/JSON body, generic error
  try {
    const r = await pool.query(`SELECT name FROM members WHERE email = '${req.body.email || ""}'`);
    res.send(page("lookup", r.rows.length ? `<p>${escapeHtml(r.rows[0].name)}</p>` : "<p>no member</p>"));
  } catch (e) {
    res.status(500).send(page("lookup", "<p>Internal error</p>"));
  }
});
app.post("/lookup-safe", async (req, res) => { // SAFE
  const r = await pool.query("SELECT name FROM members WHERE email = $1", [String(req.body.email || "")]);
  res.send(page("lookup", r.rows.length ? `<p>${escapeHtml(r.rows[0].name)}</p>` : "<p>no member</p>"));
});
app.get("/sort", async (req, res) => { // VULN CWE-89: ORDER BY injection, errors hidden
  try {
    const r = await pool.query("SELECT title, category FROM books ORDER BY " + (req.query.by || "id"));
    res.send(page("sorted", list(r.rows)));
  } catch (e) {
    res.send(page("sorted", "<p>could not sort</p>"));
  }
});
app.get("/sort-safe", async (req, res) => { // SAFE: allowlist
  const by = ["title", "category", "id"].includes(req.query.by) ? req.query.by : "id";
  const r = await pool.query(`SELECT title, category FROM books ORDER BY ${by}`);
  res.send(page("sorted", list(r.rows)));
});

// ---------- CWE-79 ----------
app.get("/hello", (req, res) => res.send(page("hello", "<p>Hi " + (req.query.name || "") + "</p>"))); // VULN CWE-79 body
app.get("/hello-safe", (req, res) => res.send(page("hello", "<p>Hi " + escapeHtml(req.query.name || "") + "</p>"))); // SAFE
app.get("/banner", (req, res) => res.send(page("banner", `<input type="text" value='${req.query.msg || ""}'>`))); // VULN CWE-79 single-quoted attribute
app.get("/banner-safe", (req, res) => res.send(page("banner", `<input type="text" value='${escapeHtml(req.query.msg || "")}'>`))); // SAFE
app.get("/api/echo", (req, res) => res.json({ q: req.query.q || "" })); // SAFE (hard negative): JSON reflection
app.get("/members", async (req, res) => { // SAFE: no user input
  const r = await pool.query("SELECT name FROM members ORDER BY id");
  res.send(page("members", "<ul>" + r.rows.map((m) => `<li>${escapeHtml(m.name)}</li>`).join("") + "</ul>"));
});
app.get("/members-safe", (req, res) => res.redirect(302, "/members")); // SAFE: redirect
app.get("/convert", (req, res) => { // SAFE (hard negative): 400 with a JS stack on bad input
  const n = Number(req.query.amount);
  if (Number.isNaN(n)) return res.status(400).send(page("error", `<pre>${escapeHtml(new TypeError("amount is not a number").stack)}</pre>`));
  res.send(page("convert", `<p>${(n * 1.1).toFixed(2)}</p>`));
});

// ---------- CWE-78 / CWE-22 (only after CWE-89 / CWE-79 work) ----------
app.get("/dns", (req, res) => { // VULN CWE-78
  exec("getent hosts " + (req.query.host || ""), { timeout: 5000 }, (err, out, errOut) => res.send(page("dns", `<pre>${escapeHtml(out + errOut)}</pre>`)));
});
app.get("/dns-safe", (req, res) => { // SAFE
  execFile("getent", ["hosts", String(req.query.host || "")], { timeout: 5000 }, (err, out, errOut) => res.send(page("dns", `<pre>${escapeHtml(out + errOut)}</pre>`)));
});
app.get("/file", (req, res) => { // VULN CWE-22
  fs.readFile(path.join(FILES, String(req.query.name || "")), "utf8", (err, data) => err ? res.status(404).send(page("file", "<p>missing</p>")) : res.type("text/plain").send(data.slice(0, 4096)));
});
app.get("/file-safe", (req, res) => { // SAFE
  const p = path.resolve(FILES, path.basename(String(req.query.name || "")));
  if (!p.startsWith(FILES + path.sep)) return res.status(404).send(page("file", "<p>missing</p>"));
  fs.readFile(p, "utf8", (err, data) => err ? res.status(404).send(page("file", "<p>missing</p>")) : res.type("text/plain").send(data.slice(0, 4096)));
});

// ---------- v2 additions (B3): realistic safe endpoints, vulnerable twins where they make sense ----------
const sameSite = (u) => typeof u === "string" && u.startsWith("/") && !u.startsWith("//") && !u.includes("\\");
app.get("/v2", (req, res) => {
  const links = ["/link?url=/books", "/link-safe?url=/books", "/next?next=/books", "/next-safe?next=/books", "/api/items-safe?q=Dune", "/upstream-safe?sku=A1"];
  res.send(page("labexpress v2", "<ul>" + links.map((l) => `<li><a href="${l}">${l}</a></li>`).join("") + "</ul>"));
});
app.get("/link", (req, res) => res.send(page("link", `<a href="${escapeHtml(req.query.url || "/")}">continue</a>`))); // VULN CWE-79: escaped, scheme not checked
app.get("/link-safe", (req, res) => res.send(page("link", `<a href="${escapeHtml(sameSite(req.query.url) ? req.query.url : "/")}">continue</a>`))); // SAFE
app.get("/next", (req, res) => res.redirect(302, String(req.query.next || "/"))); // VULN CWE-601
app.get("/next-safe", (req, res) => res.redirect(302, sameSite(req.query.next) ? req.query.next : "/")); // SAFE
app.get("/api/items-safe", async (req, res) => { // SAFE (hard negative): validated JSON API, 400 JSON on bad input
  const q = String(req.query.q || "");
  if (!/^[\w ]{0,40}$/.test(q)) return res.status(400).json({ error: "invalid query" });
  const r = await pool.query("SELECT title FROM books WHERE title ILIKE $1", [`%${q}%`]);
  res.json({ items: r.rows.map((x) => x.title) });
});
const SKUS = new Set(["A1", "B2"]);
app.get("/upstream-safe", (req, res) => { // SAFE (hard negative): unknown SKUs wait ~1.2 s for a slow upstream, whatever the input
  const sku = String(req.query.sku || "");
  if (SKUS.has(sku)) return res.send(page("stock", `<p>${escapeHtml(sku)}: in stock</p>`));
  setTimeout(() => res.send(page("stock", "<p>unknown item</p>")), 1200);
});

// ---------- v3: targeted twins (docs/ml-dast-v3-plan.md, B/D1) ----------
app.get("/v3", (req, res) => {
  const links = ["/v3/api/book?title=Dune", "/v3/api/book-safe?title=Dune", "/v3/text/book?id=1", "/v3/text/book-safe?id=1",
    "/v3/badge?label=new", "/v3/badge-safe?label=new", "/v3/account"];
  res.send(page("labexpress v3", "<ul>" + links.map((l) => `<li><a href="${l}">${l}</a></li>`).join("") + "</ul>"));
});
app.get("/v3/api/book", async (req, res) => { // VULN CWE-89: string-built; the pg error comes back as JSON 500
  try {
    const r = await pool.query("SELECT title, category FROM books WHERE title = '" + String(req.query.title || "") + "'");
    res.json({ book: r.rows[0] || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
app.get("/v3/api/book-safe", async (req, res) => { // SAFE (hard negative): parameterized; over-long or empty input -> JSON 422
  const t = String(req.query.title || "");
  if (!t || t.length > 30) return res.status(422).json({ error: "title must be 1-30 characters" });
  const r = await pool.query("SELECT title, category FROM books WHERE title = $1", [t]);
  res.json({ book: r.rows[0] || null });
});
app.get("/v3/text/book", async (req, res) => { // VULN CWE-89: string-built (numeric); the pg error comes back as text/plain 500
  try {
    const r = await pool.query("SELECT title FROM books WHERE id = " + String(req.query.id || "1"));
    res.type("text/plain").send((r.rows[0] ? r.rows[0].title : "no such book") + "\n");
  } catch (e) {
    res.status(500).type("text/plain").send("database error: " + e.message + "\n");
  }
});
app.get("/v3/text/book-safe", async (req, res) => { // SAFE (hard negative): integer check; bad input -> text/plain 400
  const id = String(req.query.id || "1");
  if (!/^\d{1,6}$/.test(id)) return res.status(400).type("text/plain").send(`bad request: id must be a number, got ${JSON.stringify(id)}\n`);
  const r = await pool.query("SELECT title FROM books WHERE id = $1", [Number(id)]);
  res.type("text/plain").send((r.rows[0] ? r.rows[0].title : "no such book") + "\n");
});
app.get("/v3/badge", (req, res) => res.send(page("badge", `<p><span class=${req.query.label || "new"}>badge</span></p>`))); // VULN CWE-79: unquoted attribute
app.get("/v3/badge-safe", (req, res) => res.send(page("badge", `<p><span class="${escapeHtml(req.query.label || "new")}">badge</span></p>`))); // SAFE
const account = { nickname: "reader" };
const accountPage = (res) => {
  // session cookie with SameSite=Lax: a cross-site POST does not carry it (CSRF rule: protected by the cookie)
  res.cookie("lx_session", "lab-session", { httpOnly: true, sameSite: "lax" });
  res.send(page("account", `<form method="post" action="/v3/account"><input name="nickname" value="${escapeHtml(account.nickname)}"><button>save</button></form>`));
};
app.get("/v3/account", (req, res) => accountPage(res));
app.post("/v3/account", (req, res) => { account.nickname = String(req.body.nickname || "").slice(0, 40); accountPage(res); }); // SAFE (CSRF): no token, but SameSite=Lax

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => res.status(500).send(page("error", "<p>Internal error</p>")));

init().then(() => app.listen(8080, "0.0.0.0", () => console.log("labexpress on 8080")));
