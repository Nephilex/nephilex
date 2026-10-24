"""Flow-sensitive taint: branches, guards, containers, wrappers and new sinks.

Each case is a small, realistic idiom with a vulnerable and a safe variant. They
pin the behaviour of the ``ast-python`` flow engine (``scanners/_pyflow.py``),
the regex tier's data-flow grading and the cookie checks in ``authz``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_python")

from nephilex.analysis.repository import RepositoryAnalyzer  # noqa: E402
from nephilex.core.config import Config  # noqa: E402
from nephilex.core.models import Confidence, Severity  # noqa: E402
from nephilex.core.plugin import ScannerContext, registry  # noqa: E402
from nephilex.core.project import Project  # noqa: E402

FLASK = "from flask import request, redirect, session, Flask\napp = Flask(__name__)\n"


def _scan(tmp_path, files: dict[str, str], scanner: str = "ast-python") -> list:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(registry.get_scanner(scanner)().scan(ctx))


def _rules(tmp_path, code: str, scanner: str = "ast-python") -> set[str]:
    return {f.rule_id.split(".", 1)[1] for f in _scan(tmp_path, {"app.py": code}, scanner)}


def _view(body: str) -> str:
    lines = "".join(f"    {line}\n" for line in body.strip("\n").splitlines())
    return FLASK + "@app.route('/x', methods=['POST'])\ndef view():\n" + lines


# --- 1. branch joins keep taint --------------------------------------------
@pytest.mark.parametrize(
    "sink,rule",
    [
        ("os.system('echo ' + param)", "ast-command-injection"),
        ("exec(param)", "ast-code-injection"),
        ("open('/data/' + param)", "ast-path-traversal"),
        ("cur.execute(\"SELECT * FROM t WHERE a = '%s'\" % param)", "ast-sql-injection"),
    ],
)
def test_empty_default_guard_keeps_taint(tmp_path, sink, rule):
    code = _view(f"param = request.form.get('p')\nif not param:\n    param = ''\n{sink}")
    assert rule in _rules(tmp_path, "import os\n" + code)


def test_clean_reassignment_on_every_path_clears_taint(tmp_path):
    code = _view(
        "param = request.form.get('p')\nif param:\n    param = 'a'\nelse:\n    param = 'b'\nexec(param)"
    )
    assert "ast-code-injection" not in _rules(tmp_path, code)


# --- 9. constant conditions and guards --------------------------------------
def test_constant_false_branch_is_pruned(tmp_path):
    safe = _view(
        "param = request.form.get('p')\nnum = 86\nif 7 * 42 - num > 200:\n"
        "    bar = 'constant'\nelse:\n    bar = param\nexec(bar)"
    )
    vuln = safe.replace("7 * 42 - num > 200", "7 * 18 - num > 200")
    assert "ast-code-injection" not in _rules(tmp_path, safe)
    assert "ast-code-injection" in _rules(tmp_path, vuln)


def test_constant_ternary_and_match_are_pruned(tmp_path):
    ternary = _view(
        "param = request.form.get('p')\nbar = 'x' if 7 * 18 + 106 > 200 else param\nexec(bar)"
    )
    match = _view(
        "param = request.form.get('p')\nguess = 'ABC'[1]\nmatch guess:\n"
        "    case 'A':\n        bar = param\n    case 'B':\n        bar = 'bob'\n"
        "    case _:\n        bar = param\nexec(bar)"
    )
    assert "ast-code-injection" not in _rules(tmp_path, ternary)
    assert "ast-code-injection" not in _rules(tmp_path, match)
    assert "ast-code-injection" in _rules(tmp_path, match.replace("'ABC'[1]", "'ABC'[0]"))


def test_blocklist_guards_are_not_trusted(tmp_path):
    """``'../' in p`` and "no quote inside" checks are incomplete mitigations.

    An absolute path or a backslash form slips past a ``'../'`` check, and a
    quote check says nothing about the quoting the sink uses, so neither clears
    the value: only allowlists, numeric checks and resolved-path containment do.
    """
    traversal = _view(
        "bar = request.args.get('f')\nif '../' in bar:\n    return 'no'\nopen('/data/' + bar)"
    )
    assert "ast-path-traversal" in _rules(tmp_path, traversal)
    quoted = (
        "bar = request.args.get('e')\n"
        'if not bar.startswith("\'") or not bar.endswith("\'") or "\'" in bar[1:-1]:\n'
        "    return 'bad'\neval(bar)"
    )
    assert "ast-code-injection" in _rules(tmp_path, _view(quoted))


def test_allowlist_membership_clears(tmp_path):
    code = _view(
        "c = request.args.get('c')\nif c not in ('ls', 'pwd'):\n    return 'no'\nos.system(c)"
    )
    assert "ast-command-injection" not in _rules(tmp_path, "import os\n" + code)


# --- 4. containers -----------------------------------------------------------
def test_configparser_and_dict_keys_are_tracked(tmp_path):
    conf = (
        "import configparser\nparam = request.args.get('p')\nconf = configparser.ConfigParser()\n"
        "conf.add_section('s')\nconf.set('s', 'a', 'safe')\nconf.set('s', 'b', param)\n"
        "bar = conf.get('s', 'KEY')\nexec(bar)"
    )
    assert "ast-code-injection" in _rules(tmp_path, _view(conf.replace("KEY", "b")))
    assert "ast-code-injection" not in _rules(tmp_path, _view(conf.replace("KEY", "a")))
    d = "param = request.args.get('p')\nm = {}\nm['a'] = 'safe'\nm['b'] = param\nexec(m['KEY'])"
    assert "ast-code-injection" in _rules(tmp_path, _view(d.replace("KEY", "b")))
    assert "ast-code-injection" not in _rules(tmp_path, _view(d.replace("KEY", "a")))


def test_list_append_pop_and_index(tmp_path):
    code = (
        "param = request.args.get('p')\nlst = []\nlst.append('safe')\nlst.append(param)\n"
        "lst.append('more')\nlst.pop(0)\nexec(lst[IDX])"
    )
    assert "ast-code-injection" in _rules(tmp_path, _view(code.replace("IDX", "0")))
    assert "ast-code-injection" not in _rules(tmp_path, _view(code.replace("IDX", "1")))


# --- 5. request wrappers -----------------------------------------------------
WRAPPER = (
    "class RequestWrapper:\n    def __init__(self, request):\n        self.request = request\n"
    "    def get_form_parameter(self, name):\n        return self.request.form.get(name)\n"
    "    def get_safe_value(self, name):\n        return 'bar'\n"
)


def test_same_file_wrapper_method_is_a_source(tmp_path):
    body = "w = RequestWrapper(request)\nexec(w.METHOD('p'))"
    vuln = FLASK + WRAPPER + _view(body.replace("METHOD", "get_form_parameter"))[len(FLASK) :]
    safe = vuln.replace("get_form_parameter('p')", "get_safe_value('p')")
    assert "ast-code-injection" in _rules(tmp_path, vuln)
    assert "ast-code-injection" not in _rules(tmp_path, safe)


def test_cross_file_wrapper_method_is_a_source(tmp_path):
    view = "import wrappers\n" + _view(
        "w = wrappers.RequestWrapper(request)\nexec(w.get_form_parameter('p'))"
    )
    findings = _scan(tmp_path, {"wrappers.py": WRAPPER, "app.py": view}, "ast-python-xfile")
    hits = [f for f in findings if f.rule_id == "ast-python-xfile.ast-code-injection"]
    assert hits and hits[0].location.path == "app.py"
    assert hits[0].confidence == Confidence.MEDIUM
    safe = view.replace("get_form_parameter", "get_safe_value")
    findings = _scan(tmp_path, {"wrappers.py": WRAPPER, "app.py": safe}, "ast-python-xfile")
    assert not [f for f in findings if f.rule_id.endswith("ast-code-injection")]


def test_wrapper_method_needs_a_request_built_receiver(tmp_path):
    code = (
        FLASK
        + WRAPPER
        + _view("other = make_other()\nexec(other.get_form_parameter('p'))")[len(FLASK) :]
    )
    assert "ast-code-injection" not in _rules(tmp_path, code)


# --- 6. pathlib ----------------------------------------------------------------
def test_pathlib_join_and_construction_are_path_sinks(tmp_path):
    join = _view(
        "import pathlib\nbar = request.args.get('f')\np = pathlib.Path('/data') / bar\np.exists()"
    )
    ctor = _view("from pathlib import Path\nbar = request.args.get('f')\nPath(bar).read_text()")
    assert "ast-path-traversal" in _rules(tmp_path, join)
    assert "ast-path-traversal" in _rules(tmp_path, ctor)


def test_resolve_and_prefix_check_clears_path(tmp_path):
    code = _view(
        "import pathlib\nbar = request.args.get('f')\nbase = pathlib.Path('/data')\n"
        "p = (base / bar).resolve()\nif not str(p).startswith(str(base)):\n    return 'no'\np.read_text()"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, code)
    unresolved = code.replace(").resolve()", ")")
    assert "ast-path-traversal" in _rules(tmp_path, unresolved)


# --- 10. SQL from a function parameter -------------------------------------------
def test_sql_formatted_from_parameter_is_low_confidence(tmp_path):
    code = "def remove(cursor, username):\n    cursor.execute(\"DELETE FROM u WHERE n = '%s'\" % username)\n"
    hits = [
        f for f in _scan(tmp_path, {"db.py": code}) if f.rule_id.endswith("ast-sql-string-building")
    ]
    assert hits and hits[0].confidence == Confidence.LOW and "CWE-89" in hits[0].cwe
    safe = "def remove(cursor, username):\n    cursor.execute('DELETE FROM u WHERE n = %s', (username,))\n"
    assert not _scan(tmp_path, {"db.py": safe})
    numeric = (
        "def remove(cursor, uid):\n    cursor.execute('DELETE FROM u WHERE id = %d' % int(uid))\n"
    )
    assert not _scan(tmp_path, {"db.py": numeric})


# --- new classes -------------------------------------------------------------------
def test_reflected_xss_from_a_flask_view(tmp_path):
    vuln = _view("name = request.args.get('n')\nreturn f'<p>Hello {name}</p>'")
    assert "ast-xss" in _rules(tmp_path, vuln)
    escaped = _view(
        "import html\nname = request.args.get('n')\nreturn f'<p>Hello {html.escape(name)}</p>'"
    )
    assert "ast-xss" not in _rules(tmp_path, escaped)
    as_json = _view("from flask import jsonify\nreturn jsonify(name=request.args.get('n'))")
    assert "ast-xss" not in _rules(tmp_path, as_json)
    helper = "def greet():\n    return f'<p>{request.args.get(\"n\")}</p>'\n"  # not a view
    assert "ast-xss" not in _rules(tmp_path, FLASK + helper)


def test_markup_of_request_data(tmp_path):
    code = _view("from markupsafe import Markup\nreturn str(Markup(request.args.get('n')))")
    assert "ast-xss" in _rules(tmp_path, code)


def test_open_redirect_and_netloc_allowlist(tmp_path):
    vuln = _view("return redirect(request.args.get('next'))")
    assert "ast-open-redirect" in _rules(tmp_path, vuln)
    guarded = _view(
        "from urllib.parse import urlparse\nnxt = request.args.get('next')\nu = urlparse(nxt)\n"
        "if u.netloc not in ['example.com']:\n    return 'no'\nreturn redirect(nxt)"
    )
    assert "ast-open-redirect" not in _rules(tmp_path, guarded)
    assert "ast-open-redirect" not in _rules(tmp_path, _view("return redirect(url_for('home'))"))


@pytest.mark.parametrize(
    "target",
    [
        "f\"/scans/{request.args['id']}\"",
        "'/items/' + request.args['id']",
        "'/items/' + request.args['id'] + '/edit?tab=' + request.args['tab']",
        "f\"https://example.com/{request.args['p']}\"",
        "'https://example.com?next=' + request.args['p']",
    ],
)
def test_redirect_whose_literal_start_fixes_the_host_is_not_reported(tmp_path, target):
    assert "ast-open-redirect" not in _rules(tmp_path, _view(f"return redirect({target})"))


@pytest.mark.parametrize(
    "target",
    [
        "'/' + request.args['n']",
        "f\"//{request.args['h']}/x\"",
        "'/\\\\' + request.args['h']",
        "f\"https://{request.args['h']}/x\"",
        "'https://example.com' + request.args['p']",
        "'https://example.com@' + request.args['p']",
        "f\"{request.args['n']}/home\"",
    ],
)
def test_redirect_whose_host_can_still_change_is_reported(tmp_path, target):
    assert "ast-open-redirect" in _rules(tmp_path, _view(f"return redirect({target})"))


def test_xxe_needs_external_entities_and_tainted_xml(tmp_path):
    vuln = _view(
        "import xml.sax, xml.dom.minidom\nxml_doc = request.data\nparser = xml.sax.make_parser()\n"
        "parser.setFeature(xml.sax.handler.feature_external_ges, True)\n"
        "xml.dom.minidom.parseString(xml_doc, parser)"
    )
    assert "ast-xxe" in _rules(tmp_path, vuln)
    default = vuln.replace(
        "parser.setFeature(xml.sax.handler.feature_external_ges, True)\n    ", ""
    )
    assert "ast-xxe" not in _rules(tmp_path, default)
    lxml = _view(
        "from lxml import etree\np = etree.XMLParser(resolve_entities=True)\n"
        "etree.fromstring(request.data, p)"
    )
    assert "ast-xxe" in _rules(tmp_path, lxml)


def test_weak_random_for_session_values(tmp_path):
    vuln = "import random\ndef remember(store):\n    value = str(random.getrandbits(32))\n    store_session = {}\n    store_session['id'] = value\n"
    assert "ast-weak-random" in _rules(tmp_path, vuln)
    token = "import random\ndef make():\n    reset_token = ''.join(random.choice('abc') for _ in range(8))\n    return reset_token\n"
    assert "ast-weak-random" in _rules(tmp_path, token)
    strong = vuln.replace("random.getrandbits(32)", "random.SystemRandom().getrandbits(32)")
    assert "ast-weak-random" not in _rules(tmp_path, strong)
    harmless = (
        "import random\ndef shuffle_deck(deck):\n    pick = random.choice(deck)\n    return pick\n"
    )
    assert "ast-weak-random" not in _rules(tmp_path, harmless)


def test_ldap_injection_needs_ldap_and_no_escaping(tmp_path):
    vuln = "import ldap3\n" + _view(
        "user = request.args.get('u')\nconn.search('ou=users', f'(uid={user})')"
    )
    assert "ast-ldap-injection" in _rules(tmp_path, vuln)
    escaped = vuln.replace("f'(uid={user})'", "f'(uid={escape_filter_chars(user)})'")
    assert "ast-ldap-injection" not in _rules(tmp_path, escaped)
    no_ldap = _view("import re\nuser = request.args.get('u')\nre.search('x', user)")
    assert "ast-ldap-injection" not in _rules(tmp_path, no_ldap)


def test_xpath_injection_and_variables(tmp_path):
    vuln = "import lxml.etree\n" + _view(
        "emp = request.args.get('id')\nroot = lxml.etree.parse('e.xml')\n"
        "root.xpath(f\"/E[@id='{emp}']\")"
    )
    assert "ast-xpath-injection" in _rules(tmp_path, vuln)
    variables = vuln.replace("root.xpath(f\"/E[@id='{emp}']\")", "root.xpath('/E[@id=$v]', v=emp)")
    assert "ast-xpath-injection" not in _rules(tmp_path, variables)
    quote_guard = vuln.replace("root = ", "if \"'\" in emp:\n        return 'no'\n    root = ")
    assert "ast-xpath-injection" in _rules(tmp_path, quote_guard)  # a blocklist, not trusted


def test_trust_boundary_session_store(tmp_path):
    assert "ast-trust-boundary" in _rules(
        tmp_path, _view("session['user'] = request.args.get('u')")
    )
    assert "ast-trust-boundary" in _rules(tmp_path, _view("session[request.args.get('k')] = '1'"))
    assert "ast-trust-boundary" not in _rules(tmp_path, _view("session['user'] = 'guest'"))


def test_static_route_path_is_not_attacker_controlled(tmp_path):
    static = _view("seg = request.path.split('/')[1]\nexec(seg)")
    assert "ast-code-injection" not in _rules(tmp_path, static)
    dynamic = static.replace("@app.route('/x'", "@app.route('/x/<path:rest>'")
    assert "ast-code-injection" in _rules(tmp_path, dynamic)


def test_unsafe_deserialization_of_request_data(tmp_path):
    vuln = _view("import pickle, base64\npickle.loads(base64.b64decode(request.args.get('d')))")
    assert "ast-unsafe-deserialization" in _rules(tmp_path, vuln)
    safe_yaml = _view("import yaml\nyaml.load(request.data, Loader=yaml.SafeLoader)")
    assert "ast-unsafe-deserialization" not in _rules(tmp_path, safe_yaml)


# --- regex tier graded by data flow (gaps 2, 7, 8) ------------------------------------
def _patterns(tmp_path, code: str) -> list:
    return _scan(tmp_path, {"app.py": code}, "patterns")


def test_hashlib_new_weak_algorithms(tmp_path):
    for algo in ("'md5'", '"sha1"', "name='MD5'"):
        hits = _patterns(tmp_path, f"import hashlib\nh = hashlib.new({algo})\n")
        assert any(f.rule_id == "patterns.weak-hash-md5-sha1" for f in hits), algo
    assert not _patterns(tmp_path, "import hashlib\nh = hashlib.new('sha256')\n")
    assert not _patterns(
        tmp_path, "import hashlib\nh = hashlib.new('md5', usedforsecurity=False)\n"
    )


def test_shell_true_with_constant_command_is_dropped(tmp_path):
    const = "import subprocess\nsubprocess.run('ls -l', shell=True)\n"
    built = "import subprocess, platform\nc = 'cmd /c ' if platform.system() == 'Windows' else 'sh -c '\nc += 'echo hi'\nsubprocess.run(c, shell=True)\n"
    unknown = "import subprocess\ndef run(c):\n    subprocess.run(c, shell=True)\n"
    assert not [f for f in _patterns(tmp_path, const) if "shell-true" in f.rule_id]
    assert not [f for f in _patterns(tmp_path, built) if "shell-true" in f.rule_id]
    kept = [f for f in _patterns(tmp_path, unknown) if "shell-true" in f.rule_id]
    assert kept and kept[0].metadata.get("dataflow") == "unknown"


def test_pickle_of_literal_dropped_yaml_graded(tmp_path):
    lit = "import pickle, base64\nb = 'gAN9'\npickle.loads(base64.b64decode(b))\n"
    assert not [f for f in _patterns(tmp_path, lit) if "pickle" in f.rule_id]
    unknown = "import pickle\ndef load(blob):\n    return pickle.loads(blob)\n"
    assert [f for f in _patterns(tmp_path, unknown) if "pickle" in f.rule_id]
    yaml_lit = "import yaml\ny = yaml.load('a: 1', Loader=yaml.Loader)\n"
    graded = [f for f in _patterns(tmp_path, yaml_lit) if "yaml-load" in f.rule_id]
    assert graded and graded[0].severity == Severity.LOW and graded[0].confidence == Confidence.LOW
    yaml_req = FLASK + "def v():\n    return yaml.load(request.data)\n"
    graded = [
        f for f in _patterns(tmp_path, "import yaml\n" + yaml_req) if "yaml-load" in f.rule_id
    ]
    assert (
        graded and graded[0].severity == Severity.HIGH and graded[0].confidence == Confidence.HIGH
    )


def test_template_safe_filter(tmp_path):
    findings = _scan(
        tmp_path,
        {"app.py": "x = 1\n", "templates/page.html": "<p>{{ bio|safe }}</p>\n<p>{{ name }}</p>\n"},
        "patterns",
    )
    hits = [f for f in findings if f.rule_id == "patterns.template-unescaped-output"]
    assert [f.location.start_line for f in hits] == [1]


# --- 3. cookies -------------------------------------------------------------------
def _cookie(tmp_path, args: str) -> set[str]:
    code = FLASK + "def v(resp, value):\n    resp.set_cookie('sid', value,\n        " + args + ")\n"
    return {f.rule_id for f in _scan(tmp_path, {"app.py": code}, "authz")}


def test_set_cookie_flags(tmp_path):
    insecure = _cookie(tmp_path, "secure=False, httponly=True")
    assert insecure == {"authz.insecure-session-cookie"}
    assert _cookie(tmp_path, "secure=True, httponly=True") == set()
    assert _cookie(tmp_path, "secure=True") == {"authz.cookie-missing-httponly"}
    assert _cookie(tmp_path, "secure=app.config['S'], httponly=True") == set()


def test_set_cookie_in_comments_and_strings_is_ignored(tmp_path):
    code = (
        "# call resp.set_cookie(name, value) with secure=True\n"
        "HELP = 'resp.set_cookie(x) needs secure=True'\n"
        'def doc():\n    """Wraps ``resp.set_cookie(...)``."""\n'
    )
    assert not _scan(tmp_path, {"app.py": code}, "authz")


def test_cookiejar_set_cookie_is_not_a_response_cookie(tmp_path):
    code = "def add(jar, cookie):\n    jar.set_cookie(cookie)\n"
    assert not _scan(tmp_path, {"app.py": code}, "authz")


def test_path_sinks_use_the_path_argument_only(tmp_path):
    # send_file's second argument is the WSGI environ, not a path; an
    # arbitrary object's .open() (a test client) is not a file API.
    code = _view(
        "from io import BytesIO\nfrom flask import send_file\n"
        "send_file(BytesIO(b'x'), request.environ)\nclient.open(request.args.get('u'))"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, code)
    assert "ast-path-traversal" in _rules(tmp_path / "b", _view("send_file(request.args.get('f'))"))


def test_any_containment_guard_clears_path(tmp_path):
    code = _view(
        "import pathlib\nroots = [pathlib.Path('/a'), pathlib.Path('/b')]\n"
        "p = (roots[0] / request.args.get('f')).resolve()\n"
        "if not any(p == r or p.is_relative_to(r) for r in roots):\n    return 'no'\n"
        "p.exists()"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, code)
    unguarded = code.replace("not any(p == r or p.is_relative_to(r) for r in roots)", "False")
    assert "ast-path-traversal" in _rules(tmp_path, unguarded)


def test_set_cookie_cwe_and_columns(tmp_path):
    code = FLASK + "def v(resp):\n    resp.set_cookie('sid', 'x', secure=False, httponly=True)\n"
    (f,) = _scan(tmp_path, {"app.py": code}, "authz")
    assert f.cwe == ["CWE-614"] and f.confidence == Confidence.HIGH
    assert f.location.snippet.startswith("    resp.set_cookie(")
    assert f.location.start_column == 5


# --- Location columns and snippets ------------------------------------------------
def test_ast_finding_has_columns_and_indented_snippet(tmp_path):
    code = _view("name = request.args.get('n')\nexec(name)")
    (f,) = [x for x in _scan(tmp_path, {"app.py": code}) if x.rule_id.endswith("code-injection")]
    assert f.location.snippet == "    exec(name)"
    assert (f.location.start_column, f.location.end_column) == (5, 15)


def test_pattern_finding_has_columns_and_indented_snippet(tmp_path):
    code = "import hashlib\ndef h(x):\n    return hashlib.md5(x)\n"
    (f,) = [x for x in _patterns(tmp_path, code) if "weak-hash" in x.rule_id]
    assert f.location.snippet == "    return hashlib.md5(x)"
    assert (f.location.start_column, f.location.end_column) == (12, 24)


def test_inline_urlparse_allowlist_and_inline_resolve(tmp_path):
    redirect_guard = _view(
        "from urllib.parse import urlparse\nt = request.args.get('next')\n"
        "if urlparse(t).netloc not in ('example.com',):\n    return 'no'\nreturn redirect(t)"
    )
    assert "ast-open-redirect" not in _rules(tmp_path, redirect_guard)
    resolved = _view(
        "import pathlib\nbase = pathlib.Path('/data')\n"
        "p = (base / request.args.get('f')).resolve()\n"
        "if not str(p).startswith(str(base)):\n    return 'no'\nreturn p.read_text()"
    )
    assert not _rules(tmp_path, resolved)


def test_hostile_nesting_stays_bounded(tmp_path):
    import time

    loops = (
        "def f(x):\n"
        + "".join("    " * (i + 1) + f"for v{i} in x:\n" for i in range(55))
        + "    " * 56
        + "x = v0\n"
    )
    ifs = "def g(x):\n" + "".join("    " * (i + 1) + f"if x > {i}:\n" for i in range(90))
    ifs += "    " * 91 + "eval(input())\n"
    start = time.perf_counter()
    findings = _scan(tmp_path, {"loops.py": loops, "ifs.py": ifs})
    assert time.perf_counter() - start < 20
    # Past the nesting limit the flat fallback still sees the tainted eval.
    assert any(f.rule_id.endswith("ast-code-injection") for f in findings)


def test_compile_is_a_code_sink_but_parameters_are_not_sources(tmp_path):
    assert "ast-code-injection" in _rules(
        tmp_path, _view("compile(request.args.get('c'), 'x', 'exec')")
    )
    # eval/exec of a plain function parameter is common in template engines and
    # debuggers; with no traced source it is not reported.
    assert not _scan(tmp_path / "b", {"m.py": "def run(code, ns):\n    exec(code, ns)\n"})
    assert not _scan(tmp_path / "d", {"m.py": "import re\ndef pat(p):\n    return re.compile(p)\n"})


def test_location_header_redirect(tmp_path):
    vuln = _view(
        "from flask import Response\nr = Response('', 302)\nr.headers['Location'] = request.args['next']\nreturn r"
    )
    assert "ast-open-redirect" in _rules(tmp_path, vuln)
    safe = vuln.replace("request.args['next']", "'/home'")
    assert "ast-open-redirect" not in _rules(tmp_path, safe)


def test_lxml_resolve_entities_rule(tmp_path):
    code = "from lxml import etree\np = etree.XMLParser(resolve_entities=True)\n"
    assert [f for f in _patterns(tmp_path, code) if f.rule_id.endswith("xml-resolve-entities")]
    safe = "from lxml import etree\np = etree.XMLParser(resolve_entities=False)\n"
    assert not _patterns(tmp_path, safe)


def test_module_level_literal_constants_are_literal_in_functions(tmp_path):
    const = "import subprocess\nCMD = 'df -h'\ndef disk():\n    subprocess.run(CMD, shell=True)\n"
    assert not [f for f in _patterns(tmp_path, const) if "shell-true" in f.rule_id]
    rebound = const + "def reset():\n    global CMD\n    CMD = input()\n"
    assert [f for f in _patterns(tmp_path, rebound) if "shell-true" in f.rule_id]
