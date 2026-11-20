from sastml import extract as ex

PY = '''import os
SECRET_KEY = "s3cr3t-value-123"

@app.route("/u")
def show_user():
    uid = request.args.get("id")
    cur.execute("SELECT * FROM u WHERE id=" + uid)
    return "ok"

class Repo:
    def find(self, name):
        def helper(x):
            return x
        return helper(name)
'''

JS = '''const express = require('express');
const password = 'hunter2hunter2';
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});
module.exports.search = function (req, res) {
  db.query("SELECT 1").then(rows => {
    res.render('x', { rows });
  });
};
function Handler(db) {
  this.a = (req, res) => {
    res.send('a');
    res.send('a');
    res.send('a');
    res.send('a');
    res.send('a');
    res.send('a');
  };
  this.b = function (req, res) {
    res.send('b');
    res.send('b');
    res.send('b');
    res.send('b');
    res.send('b');
    res.send('b');
  };
}
'''


def by_name(units):
    return {u.name: u for u in units}


def test_python_functions_methods_decorators_and_module():
    units = by_name(ex.extract("app.py", PY))
    assert set(units) == {"show_user", "find", "<module>"}
    assert units["show_user"].start_line == 5, "start line is the def line"
    assert units["show_user"].code.startswith('@app.route("/u")'), "decorators are part of the unit code"
    assert "def helper" in units["find"].code, "small nested helpers stay inside their parent"
    assert "SECRET_KEY" in units["<module>"].code and "import os" not in units["<module>"].code


def test_javascript_route_callbacks_and_containers():
    units = by_name(ex.extract("app.js", JS))
    assert "app.get '/ping'" in units
    ping = units["app.get '/ping'"]
    assert ping.start_line == 3 and ping.code.startswith("app.get('/ping'"), "route callback carries its registration"
    assert "module.exports.search" in units, "promise callbacks do not split a handler"
    assert "this.a" in units and "this.b" in units and "Handler" not in units, "container functions split into members"
    assert "password" in units["<module>"].code


def test_skips_unsupported_large_and_minified_files():
    assert ex.extract("notes.md", "def f(): pass") == []
    assert ex.extract("big.js", "x".join(["a"] * (ex.MAX_FILE_BYTES + 10))) == []
    assert ex.extract("min.js", "function a(){return 1};" * 400) == []


def test_python_syntax_error_yields_nothing():
    assert ex.extract("bad.py", "def broken(:\n  pass") == []


def test_fallback_parser(monkeypatch):
    monkeypatch.setattr(ex, "_JS_PARSER", False)
    units = ex.extract("a.js", "function hello(a) {\n  const s = '}';\n  return a;\n}\nconst f = async (x) => {\n  return x;\n};\n")
    names = [u.name for u in units]
    assert names[:2] == ["hello", "<anonymous>"] and all(u.parser == "fallback" for u in units)
    assert units[0].end_line == 4, "braces inside strings are skipped"
