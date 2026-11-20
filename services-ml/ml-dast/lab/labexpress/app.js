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
    "/file?name=guide.txt", "/file-safe?name=guide.txt"];
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

init().then(() => app.listen(8080, "0.0.0.0", () => console.log("labexpress on 8080")));
