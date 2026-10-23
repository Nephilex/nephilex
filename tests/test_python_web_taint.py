"""Path traversal, XSS, SSRF and code/template injection in the Python taint engine.

Every source, sink and sanitizer added to ``scanners/_pyflow.py`` for these
classes has a vulnerable snippet that must be reported and a fixed twin that
must not. The snippets use the real framework APIs (Flask, FastAPI/Starlette,
requests, httpx, aiohttp, urllib, tarfile, zipfile, Jinja2, markupsafe).
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_python")

from nephilex.analysis.repository import RepositoryAnalyzer  # noqa: E402
from nephilex.core.config import Config  # noqa: E402
from nephilex.core.plugin import ScannerContext, registry  # noqa: E402
from nephilex.core.project import Project  # noqa: E402

FLASK = "import os\nfrom flask import Flask, request, send_file, send_from_directory\n"
FLASK += "app = Flask(__name__)\n"
FASTAPI = "import os\nfrom fastapi import FastAPI, File, Query, Request, UploadFile\n"
FASTAPI += "from fastapi.responses import FileResponse, HTMLResponse\napp = FastAPI()\n"


def _findings(tmp_path, code: str, name: str = "app.py") -> list:
    (tmp_path / name).write_text(code, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(registry.get_scanner("ast-python")().scan(ctx))


def _rules(tmp_path, code: str) -> set[str]:
    return {f.rule_id.split(".", 1)[1] for f in _findings(tmp_path, code)}


def _flask_view(rule: str, params: str, body: str) -> str:
    lines = "".join(f"    {line}\n" for line in body.strip("\n").splitlines())
    return FLASK + f"@app.route('{rule}')\ndef view({params}):\n" + lines


def _fastapi_view(decorator: str, params: str, body: str, prelude: str = "") -> str:
    lines = "".join(f"    {line}\n" for line in body.strip("\n").splitlines())
    return FASTAPI + prelude + f"@app.{decorator}\nasync def view({params}):\n" + lines


# --- sources: framework parameters -------------------------------------------
def test_flask_path_converter_is_a_source(tmp_path):
    code = _flask_view(
        "/files/<path:name>", "name", "return send_file(os.path.join('/srv/files', name))"
    )
    assert "ast-path-traversal" in _rules(tmp_path, code)


def test_flask_int_converter_is_not_a_source(tmp_path):
    code = _flask_view(
        "/files/<int:num>", "num", "return send_file(os.path.join('/srv/files', str(num)))"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, code)


def test_flask_send_from_directory_is_safe_for_the_file_name(tmp_path):
    """Flask joins the name with werkzeug.security.safe_join."""
    code = _flask_view("/files/<path:name>", "name", "return send_from_directory('/srv', name)")
    assert "ast-path-traversal" not in _rules(tmp_path, code)
    tainted_dir = _flask_view(
        "/files", "", "return send_from_directory(request.args['d'], 'index.html')"
    )
    assert "ast-path-traversal" in _rules(tmp_path, tainted_dir)


def test_fastapi_query_parameter_is_a_source(tmp_path):
    code = _fastapi_view(
        "get('/read')", "name: str = Query(...)", "return FileResponse(os.path.join('/srv', name))"
    )
    assert "ast-path-traversal" in _rules(tmp_path, code)


def test_fastapi_path_operation_parameters_are_sources_except_numbers(tmp_path):
    code = _fastapi_view("get('/read/{name}')", "name: str", "return FileResponse('/srv/' + name)")
    assert "ast-path-traversal" in _rules(tmp_path, code)
    number = _fastapi_view("get('/read/{n}')", "n: int", "return FileResponse('/srv/' + str(n))")
    assert "ast-path-traversal" not in _rules(tmp_path, number)


def test_fastapi_dependency_parameter_is_not_a_source(tmp_path):
    code = _fastapi_view(
        "get('/read')",
        "name: str = Depends(get_name)",
        "return FileResponse('/srv/' + name)",
        prelude="from fastapi import Depends\n",
    )
    assert "ast-path-traversal" not in _rules(tmp_path, code)


def test_starlette_request_object_attributes_are_sources(tmp_path):
    code = FASTAPI + (
        "async def page(req: Request):\n"
        "    name = req.query_params.get('f')\n"
        "    return FileResponse(os.path.join('/srv', name))\n"
    )
    assert "ast-path-traversal" in _rules(tmp_path, code)


def test_upload_file_name_is_a_source_and_secure_filename_clears_it(tmp_path):
    vuln = _fastapi_view(
        "post('/up')",
        "f: UploadFile = File(...)",
        "with open(os.path.join('/srv/up', f.filename), 'wb') as out:\n"
        "    out.write(await f.read())",
    )
    assert "ast-path-traversal" in _rules(tmp_path, vuln)
    fixed = vuln.replace("f.filename", "secure_filename(f.filename)")
    fixed = fixed.replace("import os\n", "import os\nfrom werkzeug.utils import secure_filename\n")
    assert "ast-path-traversal" not in _rules(tmp_path, fixed)


# --- path traversal: sinks and sanitizers ----------------------------------------
def test_pathlib_division_by_a_string_makes_a_path(tmp_path):
    code = _flask_view(
        "/x", "", "base = load_base()\n(base / f\"{request.args['n']}.txt\").read_text()"
    )
    assert "ast-path-traversal" in _rules(tmp_path, code)


def test_commonpath_containment_check_clears_a_resolved_path(tmp_path):
    body = (
        "root = os.path.realpath('/srv')\n"
        "p = os.path.realpath(os.path.join(root, request.args['f']))\n"
        "if os.path.commonpath([root, p]) != root:\n"
        "    raise ValueError('outside')\n"
        "return send_file(p)"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, _flask_view("/x", "", body))
    unresolved = body.replace("p = os.path.realpath(os.path.join", "p = (os.path.join")
    assert "ast-path-traversal" in _rules(tmp_path, _flask_view("/x", "", unresolved))


def test_or_of_containment_checks_clears(tmp_path):
    body = (
        "base = os.path.realpath('/srv')\n"
        "p = os.path.realpath(os.path.join(base, request.args['f']))\n"
        "if not (p.startswith(base + os.sep) or p == base):\n"
        "    raise PermissionError('outside')\n"
        "return send_file(p)"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, _flask_view("/x", "", body))


def test_zip_member_name_is_a_source(tmp_path):
    code = (
        "import os, zipfile\n"
        "def unpack(archive, dest):\n"
        "    with zipfile.ZipFile(archive) as zf:\n"
        "        for info in zf.infolist():\n"
        "            target = os.path.join(dest, info.filename)\n"
        "            with open(target, 'wb') as out:\n"
        "                out.write(zf.read(info))\n"
    )
    findings = [f for f in _findings(tmp_path, code) if f.rule_id.endswith("ast-path-traversal")]
    assert findings and "archive-entry" in findings[0].tags
    assert findings[0].metadata["source"] == "archive-entry"
    fixed = code.replace(
        "            with open(target, 'wb') as out:\n",
        "            target = os.path.realpath(target)\n"
        "            if os.path.commonpath([os.path.realpath(dest), target]) != os.path.realpath(dest):\n"
        "                raise ValueError(info.filename)\n"
        "            with open(target, 'wb') as out:\n",
    )
    fixed = fixed.replace("[os.path.realpath(dest), target]", "[root, target]").replace(
        "!= os.path.realpath(dest)", "!= root"
    )
    fixed = fixed.replace(
        "    with zipfile.ZipFile", "    root = os.path.realpath(dest)\n    with zipfile.ZipFile"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, fixed)


def test_tar_name_list_and_basename(tmp_path):
    code = (
        "import os, tarfile\n"
        "def unpack(path, dest):\n"
        "    tar = tarfile.open(path)\n"
        "    for name in tar.getnames():\n"
        "        open(os.path.join(dest, name), 'wb')\n"
    )
    assert "ast-path-traversal" in _rules(tmp_path, code)
    fixed = code.replace("os.path.join(dest, name)", "os.path.join(dest, os.path.basename(name))")
    assert "ast-path-traversal" not in _rules(tmp_path, fixed)


@pytest.mark.parametrize(
    "call,reported",
    [
        ("tar.extractall('/srv/data')", True),
        ("tar.extractall('/srv/data', filter='fully_trusted')", True),
        ("tar.extractall('/srv/data', filter='data')", False),
        ("tar.extractall('/srv/data', filter=tarfile.data_filter)", False),
        ("tar.extractall('/srv/data', members=safe_members(tar))", False),
        ("tar.extract('a.txt', '/srv/data')", True),
    ],
)
def test_tar_extraction_without_a_filter(tmp_path, call, reported):
    code = FLASK + (
        "import tarfile\n"
        "@app.route('/up', methods=['POST'])\n"
        "def up():\n"
        "    tar = tarfile.open(fileobj=request.files['f'].stream)\n"
        f"    {call}\n"
    )
    assert ("ast-archive-extraction" in _rules(tmp_path, code)) is reported


def test_shutil_unpack_archive_without_a_filter(tmp_path):
    code = _flask_view("/x", "", "import shutil\nshutil.unpack_archive(request.args['a'], '/srv')")
    assert "ast-archive-extraction" in _rules(tmp_path, code)
    assert "ast-archive-extraction" not in _rules(
        tmp_path, code.replace("'/srv')", "'/srv', filter='data')")
    )


def test_tar_from_a_trusted_path_is_not_reported(tmp_path):
    code = "import tarfile\ndef setup():\n    tarfile.open('bundle.tar').extractall('out')\n"
    assert "ast-archive-extraction" not in _rules(tmp_path, code)


# --- SSRF ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "fetch",
    [
        "requests.get(url)",
        "requests.request('GET', url)",
        "httpx.post(url, json={})",
        "urllib.request.urlopen(url)",
        "requests.Session().get(url)",
    ],
)
def test_outbound_request_to_a_url_from_input(tmp_path, fetch):
    code = _flask_view(
        "/fetch", "", f"import requests, httpx, urllib.request\nurl = request.args['u']\n{fetch}"
    )
    assert "ast-ssrf" in _rules(tmp_path, code)


def test_aiohttp_client_session_with_fastapi_query(tmp_path):
    code = _fastapi_view(
        "get('/proxy')",
        "url: str = Query(...)",
        "async with aiohttp.ClientSession() as session:\n"
        "    async with session.get(url) as response:\n"
        "        return await response.read()",
        prelude="import aiohttp\n",
    )
    assert "ast-ssrf" in _rules(tmp_path, code)


def test_module_level_http_client_object(tmp_path):
    code = FLASK + (
        "import httpx\nclient = httpx.Client()\n"
        "@app.route('/f')\ndef f():\n    return client.get(request.args['u']).text\n"
    )
    assert "ast-ssrf" in _rules(tmp_path, code)


def test_constant_url_is_not_reported(tmp_path):
    code = _flask_view(
        "/f", "", "import requests\nreturn requests.get('https://api.example.com/x').text"
    )
    assert "ast-ssrf" not in _rules(tmp_path, code)


@pytest.mark.parametrize(
    "guard",
    [
        "if urlparse(url).hostname not in ALLOWED:\n    return 'no'",
        "if not urlparse(url).hostname.endswith('.example.com'):\n    return 'no'",
        "host = urlparse(url)\nif host.netloc != 'api.example.com':\n    return 'no'",
    ],
)
def test_host_allowlist_clears_ssrf(tmp_path, guard):
    body = (
        "import requests\nfrom urllib.parse import urlparse\nALLOWED = ('api.example.com',)\n"
        f"url = request.args['u']\n{guard}\nreturn requests.get(url).text"
    )
    assert "ast-ssrf" not in _rules(tmp_path, _flask_view("/f", "", body))


def test_ip_classification_validator_clears_ssrf(tmp_path):
    validator = (
        "import ipaddress, socket\nfrom urllib.parse import urlparse\n"
        "def check_url(url):\n"
        "    host = urlparse(url).hostname\n"
        "    ip = ipaddress.ip_address(socket.gethostbyname(host))\n"
        "    if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
        "        raise ValueError('internal address')\n"
    )
    vuln = (
        FLASK
        + validator
        + (
            "import requests\n@app.route('/f')\ndef f():\n"
            "    url = request.args['u']\n    return requests.get(url).text\n"
        )
    )
    assert "ast-ssrf" in _rules(tmp_path, vuln)
    fixed = vuln.replace(
        "    return requests.get(url).text", "    check_url(url)\n    return requests.get(url).text"
    )
    assert "ast-ssrf" not in _rules(tmp_path, fixed)


# --- XSS -------------------------------------------------------------------------
def test_html_response_with_input(tmp_path):
    code = _fastapi_view("get('/hi')", "name: str", "return HTMLResponse(f'<b>{name}</b>')")
    assert "ast-xss" in _rules(tmp_path, code)
    escaped = code.replace("{name}", "{escape(name)}").replace(
        "import os\n", "import os\nfrom markupsafe import escape\n"
    )
    assert "ast-xss" not in _rules(tmp_path, escaped)


def test_fastapi_html_route_returning_formatted_html(tmp_path):
    code = _fastapi_view(
        "get('/hi', response_class=HTMLResponse)", "name: str", "return f'<h1>{name}</h1>'"
    )
    assert "ast-xss" in _rules(tmp_path, code)


def test_flask_route_param_returned_as_html(tmp_path):
    code = _flask_view("/hi/<name>", "name", "return f'<h1>Hello {name}</h1>'")
    assert "ast-xss" in _rules(tmp_path, code)


def test_format_html_escapes_its_arguments(tmp_path):
    code = _flask_view(
        "/hi",
        "",
        "from django.utils.html import format_html\nfrom django.utils.safestring import mark_safe\n"
        "return mark_safe(format_html('<b>{}</b>', request.args['n']))",
    )
    assert "ast-xss" not in _rules(tmp_path, code)
    assert "ast-xss" in _rules(tmp_path, code.replace("format_html(", "str.format("))


@pytest.mark.parametrize(
    "ctor,reported",
    [
        ("Environment(autoescape=False)", True),
        ("jinja2.Environment(loader=loader, autoescape=False)", True),
        ("Environment(autoescape=True)", False),
        ("Environment(autoescape=select_autoescape(['html']))", False),
        ("Environment()", False),
    ],
)
def test_jinja_autoescape_off(tmp_path, ctor, reported):
    code = f"import jinja2\nfrom jinja2 import Environment, select_autoescape\nenv = {ctor}\n"
    assert ("ast-jinja-autoescape-off" in _rules(tmp_path, code)) is reported


# --- template and code injection -----------------------------------------------------
@pytest.mark.parametrize(
    "render",
    [
        "render_template_string(request.args['t'])",
        "Environment().from_string(request.args['t']).render()",
        "jinja2.Template(request.args['t']).render()",
    ],
)
def test_template_source_from_input(tmp_path, render):
    code = _flask_view(
        "/t",
        "",
        "import jinja2\nfrom flask import render_template_string\nfrom jinja2 import Environment\n"
        f"return {render}",
    )
    found = [f for f in _findings(tmp_path, code) if f.rule_id.endswith("ast-template-injection")]
    assert found and set(found[0].cwe) == {"CWE-1336", "CWE-94"}


def test_sandboxed_environment_and_template_variables_are_safe(tmp_path):
    sandboxed = _flask_view(
        "/t",
        "",
        "from jinja2.sandbox import ImmutableSandboxedEnvironment\n"
        "return ImmutableSandboxedEnvironment().from_string(request.args['t']).render()",
    )
    assert "ast-template-injection" not in _rules(tmp_path, sandboxed)
    variables = _flask_view(
        "/t",
        "",
        "from flask import render_template_string\n"
        "return render_template_string('Hello {{ n }}', n=request.args['n'])",
    )
    assert "ast-template-injection" not in _rules(tmp_path, variables)


def test_string_template_is_not_jinja(tmp_path):
    code = _flask_view(
        "/t", "", "from string import Template\nreturn Template(request.args['t']).substitute(a=1)"
    )
    assert "ast-template-injection" not in _rules(tmp_path, code)


def test_closure_sees_the_enclosing_functions_taint(tmp_path):
    code = _flask_view(
        "/stream",
        "",
        "data = request.args['expr']\ndef gen():\n    yield str(eval(data))\nreturn gen()",
    )
    assert "ast-code-injection" in _rules(tmp_path, code)


# --- same-file helpers -------------------------------------------------------------
def test_sanitizing_helper_returns_a_clean_value(tmp_path):
    helper = (
        "def resolve(base, name):\n"
        "    p = os.path.realpath(os.path.join(base, name))\n"
        "    if not p.startswith(os.path.realpath(base) + os.sep):\n"
        "        raise ValueError(name)\n"
        "    return p\n"
    )
    vuln = FLASK + (
        "def resolve(base, name):\n    return os.path.join(base, name)\n"
        "@app.route('/f')\ndef f():\n    return send_file(resolve('/srv', request.args['n']))\n"
    )
    assert "ast-path-traversal" in _rules(tmp_path, vuln)
    fixed = (
        FLASK
        + helper
        + ("@app.route('/f')\ndef f():\n    return send_file(resolve('/srv', request.args['n']))\n")
    )
    assert "ast-path-traversal" not in _rules(tmp_path, fixed)


def test_helper_that_ignores_its_argument_returns_clean_data(tmp_path):
    code = FLASK + (
        "def lookup(key):\n    return DEFAULTS_PATH\n"
        "@app.route('/f')\ndef f():\n    return send_file(lookup(request.args['n']))\n"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, code)


def test_allowlist_validator_helper_clears_its_argument(tmp_path):
    code = FLASK + (
        "ALLOWED = ('a.txt', 'b.txt')\n"
        "def check(name):\n    if name not in ALLOWED:\n        raise ValueError(name)\n"
        "@app.route('/f')\ndef f():\n    name = request.args['n']\n    check(name)\n"
        "    return send_file(os.path.join('/srv', name))\n"
    )
    assert "ast-path-traversal" not in _rules(tmp_path, code)
    unchecked = code.replace("    check(name)\n", "")
    assert "ast-path-traversal" in _rules(tmp_path, unchecked)
