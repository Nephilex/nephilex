#!/usr/bin/env python3
"""Labeled-corpus accuracy benchmark: real precision and recall, no downloads.

The main harness (``run_benchmarks.py``) clones large reference apps and reports
*finding inventories*, which catch regressions but cannot give precision/recall
without a ground-truth mapping. This file is the complement: a small, fully
labeled corpus that ships in the repo so the numbers are reproducible on any
machine with one command and no network.

Each case is a single file that is either **vulnerable** (Nephilex should raise at
least one actionable finding) or **safe** (Nephilex should raise none). From that we
compute, per domain and overall:

* **Recall**    = caught vulnerable cases / all vulnerable cases  (did we miss a bug?)
* **Precision** = caught vulnerable cases / (caught + findings on safe cases)

This is deliberately a *small, honest* set. It is not a substitute for the large
public corpora (Juice Shop, WebGoat, DVWA, NIST SARD), which the main harness
covers. It exists so every release has published, reproducible accuracy numbers,
and so a regression in either direction fails CI.

    python benchmarks/accuracy.py            # print the table
    python benchmarks/accuracy.py --json     # also write results/accuracy.json
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from nephilex.core.config import Config
from nephilex.core.engine import ScanEngine
from nephilex.core.models import Severity
from nephilex.core.project import Project
from nephilex.plugins import register_builtins

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

# Only actionable findings count, both for catching bugs and for false positives.
MIN_SEVERITY = Severity.LOW


#: Prelude for the small Flask views in the flow-sensitive taint cases.
_FLASK = (
    "import os\nimport subprocess\n"
    "from flask import Flask, redirect, request, session\napp = Flask(__name__)\n"
)


@dataclass
class Case:
    name: str
    domain: str
    filename: str
    vulnerable: bool
    code: str
    #: Other files of the project (path -> text), for flows through a helper
    #: defined in another module. Findings in them count too.
    extra: dict[str, str] | None = None


# --- the labeled corpus ----------------------------------------------------
# Vulnerable cases must fire at least one finding; safe cases must fire none.
CASES: list[Case] = [
    # secrets
    Case(
        "secret-aws-key",
        "secrets",
        "config.py",
        True,
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
    ),
    Case(
        "secret-placeholder",
        "secrets",
        "config.py",
        False,
        'AWS_ACCESS_KEY_ID = "REPLACE_WITH_YOUR_KEY"  # example placeholder\n',
    ),
    # SAST: command execution through the shell
    Case(
        "sast-shell-true",
        "sast",
        "run.py",
        True,
        'import subprocess\ndef run(host):\n    subprocess.run("ping " + host, shell=True)\n',
    ),
    Case(
        "sast-shell-safe",
        "sast",
        "run.py",
        False,
        'import subprocess\ndef run(host):\n    subprocess.run(["ping", host])\n',
    ),
    # SAST: unsafe deserialization
    Case(
        "sast-yaml-load",
        "sast",
        "load.py",
        True,
        "import yaml\ndef load(raw):\n    return yaml.load(raw)\n",
    ),
    Case(
        "sast-yaml-safe",
        "sast",
        "load.py",
        False,
        "import yaml\ndef load(raw):\n    return yaml.safe_load(raw)\n",
    ),
    # SAST: weak hash
    Case(
        "sast-weak-hash",
        "sast",
        "hash.py",
        True,
        "import hashlib\ndef digest(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n",
    ),
    Case(
        "sast-strong-hash",
        "sast",
        "hash.py",
        False,
        "import hashlib\ndef digest(pw):\n    return hashlib.sha256(pw.encode()).hexdigest()\n",
    ),
    # Taint: SQL injection from a request parameter
    Case(
        "taint-sql-injection",
        "taint",
        "view.py",
        True,
        "from flask import request\n"
        "def q(cursor):\n"
        '    uid = request.args.get("id")\n'
        "    cursor.execute(\"SELECT * FROM users WHERE id = '%s'\" % uid)\n",
    ),
    Case(
        "taint-sql-parameterized",
        "taint",
        "view.py",
        False,
        "from flask import request\n"
        "def q(cursor):\n"
        '    uid = request.args.get("id")\n'
        '    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n',
    ),
    # IaC: container hardening
    Case(
        "iac-docker-latest-root",
        "iac",
        "Dockerfile",
        True,
        'FROM python:latest\nCOPY . /app\nCMD ["python", "app.py"]\n',
    ),
    Case(
        "iac-docker-pinned-nonroot",
        "iac",
        "Dockerfile",
        False,
        "FROM python:3.12-slim\n"
        "RUN useradd --create-home app\n"
        "USER app\n"
        "COPY . /app\n"
        'CMD ["python", "app.py"]\n',
    ),
    # LLM / AI security (OWASP Top 10 for LLM Apps). There is no standard public
    # benchmark for these classes, so this labeled set is itself a contribution.
    # LLM01 Prompt Injection: untrusted input concatenated into a prompt.
    Case(
        "llm-prompt-injection",
        "llm",
        "ai.py",
        True,
        "import openai\n"
        "def ask(request):\n"
        '    prompt = "Summarize: " + request.args.get("q")\n'
        '    return openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])\n',
    ),
    Case(
        "llm-prompt-injection-safe",
        "llm",
        "ai.py",
        False,
        "import openai\n"
        "def ask(request):\n"
        '    q = request.args.get("q")\n'
        '    return openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": q}])\n',
    ),
    # LLM02 Insecure Output Handling: model output flows into eval().
    Case(
        "llm-insecure-output",
        "llm",
        "ai.py",
        True,
        "import openai\n"
        "def run():\n"
        '    resp = openai.ChatCompletion.create(model="gpt-4", messages=[])\n'
        "    out = resp.choices[0].message.content\n"
        "    eval(out)\n",
    ),
    Case(
        "llm-insecure-output-safe",
        "llm",
        "ai.py",
        False,
        "import openai\n"
        "import json\n"
        "def run():\n"
        '    resp = openai.ChatCompletion.create(model="gpt-4", messages=[])\n'
        "    out = resp.choices[0].message.content\n"
        "    data = json.loads(out)\n"
        '    return data["answer"]\n',
    ),
    # LLM05 Supply Chain: remote code + unsafe deserialization at model load.
    Case(
        "llm-trust-remote-code",
        "llm",
        "ai.py",
        True,
        "from transformers import AutoModel\n"
        'm = AutoModel.from_pretrained("acme/x", trust_remote_code=True)\n',
    ),
    Case(
        "llm-torch-load-pickle",
        "llm",
        "ai.py",
        True,
        'import torch\nweights = torch.load("model.pt")\n',
    ),
    Case(
        "llm-torch-load-safe",
        "llm",
        "ai.py",
        False,
        'import torch\nweights = torch.load("model.pt", weights_only=True)\n',
    ),
    # LLM06 Sensitive Information Disclosure: secret embedded in a prompt.
    Case(
        "llm-secret-in-prompt",
        "llm",
        "ai.py",
        True,
        "import openai\n"
        'system_prompt = "You are a bot. Use API key sk-abcdef1234567890abcdef to authenticate."\n',
    ),
    Case(
        "llm-secret-in-prompt-safe",
        "llm",
        "ai.py",
        False,
        'import openai\nsystem_prompt = "You are a helpful assistant."\n',
    ),
    # LLM08 Excessive Agency: agent wired to a shell-execution tool.
    Case(
        "llm-agent-shell-tool",
        "llm",
        "ai.py",
        True,
        "from langchain.tools import ShellTool\ntool = ShellTool()\n",
    ),
    Case(
        "llm-agent-tool-safe",
        "llm",
        "ai.py",
        False,
        "from langchain.agents import initialize_agent\n"
        "agent = initialize_agent(tools=[], llm=None)\n",
    ),
    # LLM05 Improper Output Handling, tree-sitter data flow: model output into
    # a sink, against look-alikes that validate or constrain it first.
    Case(
        "llm-output-text-to-sql",
        "llm",
        "report.py",
        True,
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "def report(question, conn):\n"
        '    sql = llm.invoke(f"Write SQL for: {question}").content\n'
        "    return conn.execute(sql).fetchall()\n",
    ),
    Case(
        "llm-output-sql-parameterized-safe",
        "llm",
        "report.py",
        False,
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "def report(question, conn):\n"
        '    region = llm.invoke(f"Which region is this about: {question}").content\n'
        '    return conn.execute("SELECT * FROM sales WHERE region = ?", (region,)).fetchall()\n',
    ),
    Case(
        "llm-output-ssrf",
        "llm",
        "browse.py",
        True,
        "import requests\n"
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def browse(task):\n"
        "    msg = client.messages.create(model='m', max_tokens=50, messages=task)\n"
        "    return requests.get(msg.content[0].text.strip(), timeout=5).text\n",
    ),
    Case(
        "llm-output-ssrf-host-pinned-safe",
        "llm",
        "browse.py",
        False,
        "import requests\n"
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def browse(task):\n"
        "    msg = client.messages.create(model='m', max_tokens=50, messages=task)\n"
        "    slug = msg.content[0].text.strip()\n"
        '    return requests.get(f"https://api.example.com/v1/articles/{slug}", timeout=5).text\n',
    ),
    Case(
        "llm-output-shell-argv-schema-safe",
        "llm",
        "ops.py",
        False,
        "import subprocess\n"
        "from typing import Literal\n"
        "from pydantic import BaseModel\n"
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "class Action(BaseModel):\n"
        '    service: Literal["web", "worker"]\n'
        "def act(q):\n"
        "    raw = client.chat.completions.create(model='m', messages=q).choices[0].message.content\n"
        "    action = Action.model_validate_json(raw)\n"
        '    subprocess.run(["systemctl", "status", action.service], check=False)\n',
    ),
    Case(
        "llm-output-js-innerhtml",
        "llm",
        "chat.js",
        True,
        'import OpenAI from "openai";\n'
        "const openai = new OpenAI();\n"
        "export async function render(el, messages) {\n"
        '  const r = await openai.chat.completions.create({ model: "m", messages });\n'
        "  el.innerHTML = r.choices[0].message.content;\n"
        "}\n",
    ),
    Case(
        "llm-output-js-sanitized-safe",
        "llm",
        "chat.js",
        False,
        'import OpenAI from "openai";\n'
        'import DOMPurify from "dompurify";\n'
        "const openai = new OpenAI();\n"
        "export async function render(el, messages) {\n"
        '  const r = await openai.chat.completions.create({ model: "m", messages });\n'
        "  el.innerHTML = DOMPurify.sanitize(r.choices[0].message.content);\n"
        "}\n",
    ),
    # LLM06 Excessive Agency: tool handlers and over-privileged agent tools.
    Case(
        "llm-tool-handler-eval",
        "llm",
        "tools.py",
        True,
        "from mcp.server.fastmcp import FastMCP\n"
        'mcp = FastMCP("calc")\n'
        "@mcp.tool()\n"
        "def calculate(expression: str) -> str:\n"
        "    return str(eval(expression))\n",
    ),
    Case(
        "llm-tool-handler-argv-safe",
        "llm",
        "tools.py",
        False,
        "import subprocess\n"
        "from mcp.server.fastmcp import FastMCP\n"
        'mcp = FastMCP("git")\n'
        "@mcp.tool()\n"
        "def git_log(path: str) -> str:\n"
        '    return subprocess.run(["git", "log", "--", path], capture_output=True, text=True).stdout\n',
    ),
    Case(
        "llm-agent-file-toolkit",
        "llm",
        "agent.py",
        True,
        "from langchain_openai import ChatOpenAI\n"
        "from langchain.agents import create_react_agent\n"
        "from langchain_community.agent_toolkits import FileManagementToolkit\n"
        "tools = FileManagementToolkit().get_tools()\n"
        "agent = create_react_agent(ChatOpenAI(), tools, prompt)\n",
    ),
    Case(
        "llm-agent-file-toolkit-readonly-safe",
        "llm",
        "agent.py",
        False,
        "from langchain_openai import ChatOpenAI\n"
        "from langchain.agents import create_react_agent\n"
        "from langchain_community.agent_toolkits import FileManagementToolkit\n"
        "tools = FileManagementToolkit(\n"
        '    root_dir="/srv/workspace", selected_tools=["read_file", "list_directory"]\n'
        ").get_tools()\n"
        "agent = create_react_agent(ChatOpenAI(), tools, prompt)\n",
    ),
    Case(
        "llm-agent-requests-toolkit",
        "llm",
        "agent.py",
        True,
        "from langchain_openai import ChatOpenAI\n"
        "from langchain_community.agent_toolkits.openapi.toolkit import RequestsToolkit\n"
        "from langchain_community.utilities.requests import TextRequestsWrapper\n"
        "toolkit = RequestsToolkit(\n"
        "    requests_wrapper=TextRequestsWrapper(headers={}), allow_dangerous_requests=True\n"
        ")\n",
    ),
    Case(
        "llm-agent-requests-toolkit-not-enabled-safe",
        "llm",
        "agent.py",
        False,
        "from langchain_openai import ChatOpenAI\n"
        "from langchain_community.agent_toolkits.openapi.toolkit import RequestsToolkit\n"
        "from langchain_community.utilities.requests import TextRequestsWrapper\n"
        "toolkit = RequestsToolkit(requests_wrapper=TextRequestsWrapper(headers={}))\n",
    ),
    Case(
        "llm-agent-sql-toolkit-read-write",
        "llm",
        "analyst.py",
        True,
        "import os\n"
        "from langchain_openai import ChatOpenAI\n"
        "from langchain_community.utilities import SQLDatabase\n"
        "from langchain_community.agent_toolkits import SQLDatabaseToolkit\n"
        'db = SQLDatabase.from_uri(os.environ["DATABASE_URL"])\n'
        "toolkit = SQLDatabaseToolkit(db=db, llm=ChatOpenAI())\n",
    ),
    Case(
        "llm-agent-sql-toolkit-read-only-safe",
        "llm",
        "analyst.py",
        False,
        "from langchain_openai import ChatOpenAI\n"
        "from langchain_community.utilities import SQLDatabase\n"
        "from langchain_community.agent_toolkits import SQLDatabaseToolkit\n"
        'db = SQLDatabase.from_uri("sqlite:///file:analytics.db?mode=ro&uri=true")\n'
        "toolkit = SQLDatabaseToolkit(db=db, llm=ChatOpenAI())\n",
    ),
    Case(
        "llm-autogen-local-execution",
        "llm",
        "team.py",
        True,
        "import autogen\n"
        "runner = autogen.UserProxyAgent(\n"
        '    "runner", code_execution_config={"work_dir": "coding", "use_docker": False}\n'
        ")\n",
    ),
    Case(
        "llm-autogen-docker-safe",
        "llm",
        "team.py",
        False,
        "import autogen\n"
        "runner = autogen.UserProxyAgent(\n"
        '    "runner", code_execution_config={"work_dir": "coding", "use_docker": True}\n'
        ")\n",
    ),
    Case(
        "llm-crewai-unsafe-code",
        "llm",
        "crew.py",
        True,
        "from crewai import Agent\n"
        'coder = Agent(role="dev", goal="g", backstory="b",\n'
        '              allow_code_execution=True, code_execution_mode="unsafe")\n',
    ),
    Case(
        "llm-crewai-safe-mode-safe",
        "llm",
        "crew.py",
        False,
        "from crewai import Agent\n"
        'coder = Agent(role="dev", goal="g", backstory="b", allow_code_execution=True)\n',
    ),
    # LLM01 / LLM07: system prompt construction.
    Case(
        "llm-system-prompt-retrieved-docs",
        "llm",
        "rag.py",
        True,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def answer(store, q):\n"
        "    docs = store.similarity_search(q)\n"
        '    context = "\\n".join(d.page_content for d in docs)\n'
        "    return client.chat.completions.create(model='m', messages=[\n"
        '        {"role": "system", "content": "Answer using: " + context},\n'
        '        {"role": "user", "content": q},\n'
        "    ])\n",
    ),
    Case(
        "llm-system-prompt-docs-in-user-role-safe",
        "llm",
        "rag.py",
        False,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def answer(store, q):\n"
        "    docs = store.similarity_search(q)\n"
        '    context = "\\n".join(d.page_content for d in docs)\n'
        "    return client.chat.completions.create(model='m', messages=[\n"
        '        {"role": "system", "content": "Answer only from the documents."},\n'
        '        {"role": "user", "content": "<documents>" + context + "</documents>"},\n'
        "    ])\n",
    ),
    Case(
        "llm-system-prompt-internal-url",
        "llm",
        "bot.py",
        True,
        "import anthropic\n"
        'SYSTEM_PROMPT = "You are ops support. Status API: http://10.20.0.15:8080/status"\n',
    ),
    Case(
        "llm-system-prompt-public-url-safe",
        "llm",
        "bot.py",
        False,
        "import anthropic\n"
        'SYSTEM_PROMPT = "You are support. Docs: https://docs.example.com/help"\n',
    ),
    # MCP and agent configuration files (agent-config scanner).
    Case(
        "mcp-unpinned-npx",
        "mcp",
        ".mcp.json",
        True,
        '{"mcpServers": {"github": {"command": "npx",\n'
        '  "args": ["-y", "@modelcontextprotocol/server-github"],\n'
        '  "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}}}}\n',
    ),
    Case(
        "mcp-pinned-npx-safe",
        "mcp",
        ".mcp.json",
        False,
        '{"mcpServers": {"github": {"command": "npx",\n'
        '  "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"],\n'
        '  "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}}}}\n',
    ),
    Case(
        "mcp-unpinned-uvx",
        "mcp",
        ".cursor/mcp.json",
        True,
        '{"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}}\n',
    ),
    Case(
        "mcp-pinned-uvx-safe",
        "mcp",
        ".cursor/mcp.json",
        False,
        '{"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]}}}\n',
    ),
    Case(
        "mcp-hardcoded-api-key",
        "mcp",
        "claude_desktop_config.json",
        True,
        '{"mcpServers": {"brave": {"command": "node", "args": ["/opt/brave/index.js"],\n'
        '  "env": {"BRAVE_API_KEY": "BSAq8Zx3LmN7pQ2rT5vW9yK1"}}}}\n',
    ),
    Case(
        "mcp-api-key-reference-safe",
        "mcp",
        "claude_desktop_config.json",
        False,
        '{"mcpServers": {"brave": {"command": "node", "args": ["/opt/brave/index.js"],\n'
        '  "env": {"BRAVE_API_KEY": "${BRAVE_API_KEY}"}}}}\n',
    ),
    Case(
        "mcp-plaintext-remote",
        "mcp",
        ".vscode/mcp.json",
        True,
        '{\n  // team server\n  "servers": {"tools": {"type": "http",'
        ' "url": "http://mcp.example.com/mcp"}},\n}\n',
    ),
    Case(
        "mcp-https-remote-safe",
        "mcp",
        ".vscode/mcp.json",
        False,
        '{\n  // team server\n  "servers": {"tools": {"type": "http",'
        ' "url": "https://mcp.example.com/mcp"}},\n}\n',
    ),
    Case(
        "mcp-filesystem-root",
        "mcp",
        "claude_desktop_config.json",
        True,
        '{"mcpServers": {"fs": {"command": "npx", "args": ["-y",\n'
        '  "@modelcontextprotocol/server-filesystem@2025.8.21", "/"]}}}\n',
    ),
    Case(
        "mcp-filesystem-project-dir-safe",
        "mcp",
        "claude_desktop_config.json",
        False,
        '{"mcpServers": {"fs": {"command": "npx", "args": ["-y",\n'
        '  "@modelcontextprotocol/server-filesystem@2025.8.21", "/Users/alice/projects/app"]}}}\n',
    ),
    Case(
        "mcp-cline-auto-approve",
        "mcp",
        "cline_mcp_settings.json",
        True,
        '{"mcpServers": {"shell": {"command": "node", "args": ["/opt/shell/index.js"],\n'
        '  "autoApprove": ["execute_command"]}}}\n',
    ),
    Case(
        "mcp-cline-no-auto-approve-safe",
        "mcp",
        "cline_mcp_settings.json",
        False,
        '{"mcpServers": {"shell": {"command": "node", "args": ["/opt/shell/index.js"],\n'
        '  "autoApprove": []}}}\n',
    ),
    Case(
        "agent-settings-allow-all-bash",
        "mcp",
        ".claude/settings.json",
        True,
        '{"permissions": {"allow": ["Bash"]}}\n',
    ),
    Case(
        "agent-settings-scoped-bash-safe",
        "mcp",
        ".claude/settings.json",
        False,
        '{"permissions": {"allow": ["Bash(npm run test *)", "Bash(git diff *)"],'
        ' "deny": ["Read(./.env)"]}}\n',
    ),
    # --- flow-sensitive taint (added with the public-benchmark fixes) --------
    # An empty-default guard must not erase the taint of the other branch.
    Case(
        "taint-empty-default-guard",
        "taint",
        "view.py",
        True,
        _FLASK + "@app.route('/ping', methods=['POST'])\ndef ping():\n"
        "    host = request.form.get('host')\n    if not host:\n        host = ''\n"
        "    return str(os.system('ping -c 1 ' + host))\n",
    ),
    Case(
        "taint-allowlist-guard-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "@app.route('/run', methods=['POST'])\ndef run():\n"
        "    cmd = request.form.get('cmd')\n    if cmd not in ('uptime', 'date'):\n"
        "        return 'no'\n    return str(subprocess.run([cmd]).returncode)\n",
    ),
    Case(
        "taint-constant-branch-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "@app.route('/calc', methods=['POST'])\ndef calc():\n"
        "    expr = request.form.get('e')\n    limit = 86\n"
        "    if 7 * 42 - limit > 200:\n        expr = '1 + 1'\n    return str(eval(expr))\n",
    ),
    Case(
        "taint-configparser-key",
        "taint",
        "view.py",
        True,
        _FLASK + "import configparser\n@app.route('/cfg', methods=['POST'])\ndef cfg():\n"
        "    conf = configparser.ConfigParser()\n    conf.add_section('s')\n"
        "    conf.set('s', 'user', request.form.get('v'))\n    conf.set('s', 'fixed', 'x')\n"
        "    return str(eval(conf.get('s', 'user')))\n",
    ),
    Case(
        "taint-configparser-other-key-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "import configparser\n@app.route('/cfg', methods=['POST'])\ndef cfg():\n"
        "    conf = configparser.ConfigParser()\n    conf.add_section('s')\n"
        "    conf.set('s', 'user', request.form.get('v'))\n    conf.set('s', 'fixed', '1 + 1')\n"
        "    return str(eval(conf.get('s', 'fixed')))\n",
    ),
    Case(
        "taint-pathlib-join",
        "taint",
        "view.py",
        True,
        _FLASK + "import pathlib\n@app.route('/file')\ndef read_file():\n"
        "    p = pathlib.Path('/srv/files') / request.args.get('name')\n"
        "    return p.read_text()\n",
    ),
    Case(
        "taint-pathlib-resolved-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "import pathlib\n@app.route('/file')\ndef read_file():\n"
        "    base = pathlib.Path('/srv/files')\n"
        "    p = (base / request.args.get('name')).resolve()\n"
        "    if not str(p).startswith(str(base)):\n        return 'no'\n"
        "    return p.read_text()\n",
    ),
    # --- path traversal, SSRF, template injection (Python detection work) ----
    Case(
        "taint-flask-path-param",
        "taint",
        "view.py",
        True,
        _FLASK + "from flask import send_file\n@app.route('/dl/<path:name>')\ndef dl(name):\n"
        "    return send_file(os.path.join('/srv/files', name))\n",
    ),
    Case(
        "taint-flask-send-from-directory-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "from flask import send_from_directory\n@app.route('/dl/<path:name>')\n"
        "def dl(name):\n    return send_from_directory('/srv/files', name)\n",
    ),
    Case(
        "taint-fastapi-ssrf",
        "taint",
        "api.py",
        True,
        "import requests\nfrom fastapi import FastAPI, Query\napp = FastAPI()\n"
        "@app.get('/preview')\ndef preview(url: str = Query(...)):\n"
        "    return {'body': requests.get(url, timeout=5).text}\n",
    ),
    Case(
        "taint-fastapi-ssrf-allowlist-safe",
        "taint",
        "api.py",
        False,
        "import requests\nfrom urllib.parse import urlparse\nfrom fastapi import FastAPI, Query\n"
        "app = FastAPI()\nALLOWED = ('images.example.com',)\n"
        "@app.get('/preview')\ndef preview(url: str = Query(...)):\n"
        "    if urlparse(url).hostname not in ALLOWED:\n        return {'error': 'host'}\n"
        "    return {'body': requests.get(url, timeout=5).text}\n",
    ),
    Case(
        "taint-tar-upload-extractall",
        "taint",
        "view.py",
        True,
        _FLASK + "import tarfile\n@app.route('/import', methods=['POST'])\ndef imp():\n"
        "    with tarfile.open(fileobj=request.files['bundle'].stream) as tar:\n"
        "        tar.extractall('/srv/import')\n    return 'ok'\n",
    ),
    Case(
        "taint-tar-upload-data-filter-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "import tarfile\n@app.route('/import', methods=['POST'])\ndef imp():\n"
        "    with tarfile.open(fileobj=request.files['bundle'].stream) as tar:\n"
        "        tar.extractall('/srv/import', filter='data')\n    return 'ok'\n",
    ),
    Case(
        "taint-render-template-string",
        "taint",
        "view.py",
        True,
        _FLASK + "from flask import render_template_string\n@app.route('/greet')\n"
        "def greet():\n    return render_template_string(request.args.get('tpl', ''))\n",
    ),
    Case(
        "taint-render-template-string-variable-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "from flask import render_template_string\n@app.route('/greet')\n"
        "def greet():\n"
        "    return render_template_string('Hello {{ n }}', n=request.args.get('n', ''))\n",
    ),
    Case(
        "taint-zip-slip",
        "taint",
        "unpack.py",
        True,
        "import os\nimport zipfile\ndef unpack(archive, dest):\n"
        "    with zipfile.ZipFile(archive) as zf:\n        for name in zf.namelist():\n"
        "            with open(os.path.join(dest, name), 'wb') as out:\n"
        "                out.write(zf.read(name))\n",
    ),
    Case(
        "taint-zip-slip-contained-safe",
        "taint",
        "unpack.py",
        False,
        "import os\nimport zipfile\ndef unpack(archive, dest):\n"
        "    root = os.path.realpath(dest)\n"
        "    with zipfile.ZipFile(archive) as zf:\n        for name in zf.namelist():\n"
        "            target = os.path.realpath(os.path.join(root, name))\n"
        "            if os.path.commonpath([root, target]) != root:\n"
        "                raise ValueError(name)\n"
        "            with open(target, 'wb') as out:\n"
        "                out.write(zf.read(name))\n",
    ),
    Case(
        "taint-request-wrapper",
        "taint",
        "view.py",
        True,
        _FLASK
        + "class Wrapped:\n    def __init__(self, request):\n        self.request = request\n"
        "    def param(self, name):\n        return self.request.args.get(name)\n"
        "@app.route('/w')\ndef w():\n    return str(eval(Wrapped(request).param('q')))\n",
    ),
    Case(
        "taint-reflected-xss",
        "taint",
        "view.py",
        True,
        _FLASK + "@app.route('/hello')\ndef hello():\n"
        "    return f\"<h1>Hello {request.args.get('name')}</h1>\"\n",
    ),
    Case(
        "taint-reflected-xss-escaped-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "from markupsafe import escape\n@app.route('/hello')\ndef hello():\n"
        "    return f\"<h1>Hello {escape(request.args.get('name'))}</h1>\"\n",
    ),
    Case(
        "taint-open-redirect",
        "taint",
        "view.py",
        True,
        _FLASK + "@app.route('/go')\ndef go():\n    return redirect(request.args.get('next'))\n",
    ),
    Case(
        "taint-open-redirect-allowlist-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "from urllib.parse import urlparse\n@app.route('/go')\ndef go():\n"
        "    target = request.args.get('next')\n"
        "    if urlparse(target).netloc not in ('example.com',):\n        return 'no'\n"
        "    return redirect(target)\n",
    ),
    Case(
        "taint-xxe-external-entities",
        "taint",
        "view.py",
        True,
        _FLASK + "import xml.sax\nimport xml.dom.minidom\n@app.route('/xml', methods=['POST'])\n"
        "def parse():\n    parser = xml.sax.make_parser()\n"
        "    parser.setFeature(xml.sax.handler.feature_external_ges, True)\n"
        "    return xml.dom.minidom.parseString(request.data, parser).toxml()\n",
    ),
    Case(
        "taint-xml-default-parser-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "import xml.dom.minidom\n@app.route('/xml', methods=['POST'])\n"
        "def parse():\n    doc = xml.dom.minidom.parseString(request.data)\n"
        "    return str(len(doc.childNodes))\n",
    ),
    Case(
        "taint-ldap-filter",
        "taint",
        "view.py",
        True,
        _FLASK + "import ldap3\n@app.route('/who')\ndef who(conn):\n"
        "    conn.search('ou=people', f\"(uid={request.args.get('u')})\")\n"
        "    return str(len(conn.entries))\n",
    ),
    Case(
        "taint-ldap-escaped-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "import ldap3\nfrom ldap3.utils.conv import escape_filter_chars\n"
        "@app.route('/who')\ndef who(conn):\n"
        "    user = escape_filter_chars(request.args.get('u'))\n"
        "    conn.search('ou=people', f'(uid={user})')\n    return str(len(conn.entries))\n",
    ),
    Case(
        "taint-xpath-expression",
        "taint",
        "view.py",
        True,
        _FLASK + "import lxml.etree\n@app.route('/emp')\ndef emp():\n"
        "    root = lxml.etree.parse('employees.xml')\n"
        "    return str(len(root.xpath(f\"//e[@id='{request.args.get('id')}']\")))\n",
    ),
    Case(
        "taint-xpath-variables-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "import lxml.etree\n@app.route('/emp')\ndef emp():\n"
        "    root = lxml.etree.parse('employees.xml')\n"
        "    return str(len(root.xpath('//e[@id=$v]', v=request.args.get('id'))))\n",
    ),
    Case(
        "taint-trust-boundary",
        "taint",
        "view.py",
        True,
        _FLASK + "@app.route('/pref', methods=['POST'])\ndef pref():\n"
        "    session['theme'] = request.form.get('theme')\n    return 'ok'\n",
    ),
    Case(
        "taint-trust-boundary-constant-safe",
        "taint",
        "view.py",
        False,
        _FLASK + "@app.route('/pref', methods=['POST'])\ndef pref():\n"
        "    session['theme'] = 'dark' if request.form.get('dark') else 'light'\n    return 'ok'\n",
    ),
    # --- through a helper imported from another file of the project -----------
    Case(
        "taint-imported-helper-path",
        "taint",
        "views.py",
        True,
        _FLASK + "from paths import under\n@app.route('/file')\ndef read_file():\n"
        "    return open(under('/srv/files', request.args.get('name'))).read()\n",
        extra={
            "paths.py": "import os\ndef under(base, name):\n    return os.path.join(base, name)\n",
        },
    ),
    Case(
        "taint-imported-validator-safe",
        "taint",
        "views.py",
        False,
        _FLASK + "from checks import require_known\n@app.route('/file')\ndef read_file():\n"
        "    name = request.args.get('name')\n    require_known(name)\n"
        "    return open(os.path.join('/srv/files', name)).read()\n",
        extra={
            "checks.py": "KNOWN = ('terms.txt', 'privacy.txt')\ndef require_known(name):\n"
            "    if name not in KNOWN:\n        raise ValueError('unknown file')\n",
        },
    ),
    # --- JavaScript / TypeScript taint (ast-js), each with a fixed twin --------
    Case(
        "taint-js-express-ssrf",
        "taint",
        "proxy.js",
        True,
        "const axios = require('axios');\n"
        "app.get('/preview', async (req, res) => {\n"
        "  const r = await axios.get(req.query.url);\n"
        "  res.json({ status: r.status });\n"
        "});\n",
    ),
    Case(
        "taint-js-express-ssrf-pinned-safe",
        "taint",
        "proxy.js",
        False,
        "const axios = require('axios');\n"
        "app.get('/preview', async (req, res) => {\n"
        "  const id = encodeURIComponent(req.query.id);\n"
        "  const r = await axios.get(`https://api.example.com/items/${id}`);\n"
        "  res.json({ status: r.status });\n"
        "});\n",
    ),
    Case(
        "taint-js-zip-slip",
        "taint",
        "unpack.js",
        True,
        "const fs = require('fs');\nconst path = require('path');\n"
        "extract.on('entry', (header, stream, next) => {\n"
        "  stream.pipe(fs.createWriteStream(path.join(dest, header.name)));\n"
        "  stream.on('end', next);\n"
        "});\n",
    ),
    Case(
        "taint-js-zip-slip-contained-safe",
        "taint",
        "unpack.js",
        False,
        "const fs = require('fs');\nconst path = require('path');\n"
        "extract.on('entry', (header, stream, next) => {\n"
        "  const target = path.resolve(dest, header.name);\n"
        "  if (!target.startsWith(path.resolve(dest) + path.sep)) return next();\n"
        "  stream.pipe(fs.createWriteStream(target));\n"
        "  stream.on('end', next);\n"
        "});\n",
    ),
    Case(
        "taint-ts-next-redirect",
        "taint",
        "route.ts",
        True,
        "import { NextRequest, NextResponse } from 'next/server';\n"
        "export async function GET(request: NextRequest) {\n"
        "  const next = request.nextUrl.searchParams.get('next');\n"
        "  return NextResponse.redirect(next as string);\n"
        "}\n",
    ),
    Case(
        "taint-ts-next-redirect-allowlist-safe",
        "taint",
        "route.ts",
        False,
        "import { NextRequest, NextResponse } from 'next/server';\n"
        "const ALLOWED = ['/home', '/settings'];\n"
        "export async function GET(request: NextRequest) {\n"
        "  const next = request.nextUrl.searchParams.get('next') ?? '/home';\n"
        "  if (!ALLOWED.includes(next)) return NextResponse.redirect(new URL('/home', request.url));\n"
        "  return NextResponse.redirect(new URL(next, request.url));\n"
        "}\n",
    ),
    Case(
        "taint-js-koa-reflected-xss",
        "taint",
        "hello.js",
        True,
        "router.get('/hello', (ctx) => {\n  ctx.body = `<h1>Hello ${ctx.query.name}</h1>`;\n});\n",
    ),
    Case(
        "taint-js-koa-escaped-safe",
        "taint",
        "hello.js",
        False,
        "const escapeHtml = require('escape-html');\n"
        "router.get('/hello', (ctx) => {\n"
        "  ctx.body = `<h1>Hello ${escapeHtml(ctx.query.name)}</h1>`;\n"
        "});\n",
    ),
    Case(
        "taint-js-static-server-traversal",
        "taint",
        "static.js",
        True,
        "const fs = require('fs');\nconst path = require('path');\n"
        "const root = path.join(path.resolve('public'), '/');\n"
        "module.exports = (req, res) => {\n"
        "  const file = path.normalize(path.join(root, decodeURIComponent(req.url)));\n"
        "  const gz = `${file}.gz`;\n"
        "  fs.createReadStream(fs.existsSync(gz) ? gz : file).pipe(res);\n"
        "};\n",
    ),
    Case(
        "taint-js-static-server-slice-check-safe",
        "taint",
        "static.js",
        False,
        "const fs = require('fs');\nconst path = require('path');\n"
        "const root = path.join(path.resolve('public'), '/');\n"
        "module.exports = (req, res) => {\n"
        "  const file = path.normalize(path.join(root, decodeURIComponent(req.url)));\n"
        "  const gz = `${file}.gz`;\n"
        "  if (file.slice(0, root.length) !== root) {\n"
        "    res.statusCode = 403;\n"
        "    return res.end();\n"
        "  }\n"
        "  fs.createReadStream(fs.existsSync(gz) ? gz : file).pipe(res);\n"
        "};\n",
    ),
    # --- regex tier with data-flow grading and new checks -------------------
    Case(
        "sast-weak-random-token",
        "sast",
        "tokens.py",
        True,
        "import random\nimport string\ndef new_reset_token():\n"
        "    return ''.join(random.choice(string.ascii_letters) for _ in range(32))\n",
    ),
    Case(
        "sast-secrets-token-safe",
        "sast",
        "tokens.py",
        False,
        "import secrets\ndef new_reset_token():\n    return secrets.token_urlsafe(32)\n",
    ),
    Case(
        "sast-hashlib-new-md5",
        "sast",
        "hash.py",
        True,
        "import hashlib\ndef digest(pw):\n    h = hashlib.new('md5')\n    h.update(pw)\n"
        "    return h.hexdigest()\n",
    ),
    Case(
        "sast-shell-constant-safe",
        "sast",
        "run.py",
        False,
        "import subprocess\ndef disk():\n    return subprocess.run('df -h', shell=True)\n",
    ),
    Case(
        "sast-pickle-literal-safe",
        "sast",
        "load.py",
        False,
        "import base64\nimport pickle\nBLOB = 'gAN9cQAu'\n"
        "def defaults():\n    return pickle.loads(base64.b64decode(BLOB))\n",
    ),
    Case(
        "sast-cookie-not-secure",
        "sast",
        "view.py",
        True,
        "def remember(resp, sid):\n    resp.set_cookie('sid', sid,\n"
        "        secure=False,\n        httponly=True)\n    return resp\n",
    ),
    Case(
        "sast-cookie-flags-safe",
        "sast",
        "view.py",
        False,
        "def remember(resp, sid):\n    resp.set_cookie('sid', sid,\n"
        "        secure=True,\n        httponly=True,\n        samesite='Lax')\n    return resp\n",
    ),
]


def _scan_case(case: Case) -> int:
    """Scan one case in isolation; return the count of actionable findings."""
    tmp = Path(tempfile.mkdtemp(prefix="nephilex-bench-"))
    try:
        target = tmp / case.filename
        target.parent.mkdir(parents=True, exist_ok=True)  # e.g. .cursor/mcp.json
        target.write_text(case.code, encoding="utf-8")
        for rel, text in (case.extra or {}).items():
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp / rel).write_text(text, encoding="utf-8")
        cfg = Config(scanner_options={"dependencies": {"online": False}})
        result = ScanEngine(cfg).scan(Project.from_path(tmp))
        return sum(1 for f in result.sorted_findings() if f.severity >= MIN_SEVERITY)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _rate(num: int, den: int) -> float:
    return num / den if den else 1.0


def main(write_json: bool = False) -> int:
    register_builtins()

    # Per-domain tallies: tp (caught vuln), fn (missed vuln), fp (findings on safe).
    domains: dict[str, dict[str, int]] = {}
    misses: list[str] = []
    false_pos: list[str] = []

    for case in CASES:
        d = domains.setdefault(case.domain, {"tp": 0, "fn": 0, "fp": 0})
        n = _scan_case(case)
        if case.vulnerable:
            if n > 0:
                d["tp"] += 1
            else:
                d["fn"] += 1
                misses.append(case.name)
        else:
            if n > 0:
                d["fp"] += n
                false_pos.append(f"{case.name} (+{n})")

    print("Nephilex, labeled-corpus accuracy")
    print("=" * 52)
    print(
        "NOTE: This is a small in-repo labeled corpus for regression detection only.\n"
        "      It is NOT a claim of real-world 100% accuracy on production codebases."
    )
    print(f"{'domain':<10} {'recall':>8} {'precision':>11} {'vuln':>6} {'safe-FP':>9}")
    print("-" * 52)
    tot = {"tp": 0, "fn": 0, "fp": 0}
    report: dict[str, object] = {
        "domains": {},
        "min_severity": MIN_SEVERITY.label,
        "scope": "labeled_corpus_v1",
        "disclaimer": (
            "Scores reflect a small in-repo labeled corpus used for regression "
            "detection only. They are not a claim of real-world accuracy on "
            "arbitrary production codebases."
        ),
    }
    for name in sorted(domains):
        d = domains[name]
        recall = _rate(d["tp"], d["tp"] + d["fn"])
        precision = _rate(d["tp"], d["tp"] + d["fp"])
        vuln = d["tp"] + d["fn"]
        print(f"{name:<10} {recall:>7.0%} {precision:>10.0%} {vuln:>6} {d['fp']:>9}")
        report["domains"][name] = {  # type: ignore[index]
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "vulnerable_cases": vuln,
            "false_positives": d["fp"],
        }
        for k in tot:
            tot[k] += d[k]

    overall_recall = _rate(tot["tp"], tot["tp"] + tot["fn"])
    overall_precision = _rate(tot["tp"], tot["tp"] + tot["fp"])
    print("-" * 52)
    print(
        f"{'OVERALL':<10} {overall_recall:>7.0%} {overall_precision:>10.0%} "
        f"{tot['tp'] + tot['fn']:>6} {tot['fp']:>9}"
    )
    report["overall"] = {
        "recall": round(overall_recall, 3),
        "precision": round(overall_precision, 3),
        "vulnerable_cases": tot["tp"] + tot["fn"],
        "false_positives": tot["fp"],
    }
    if misses:
        print("\nMissed (false negatives):", ", ".join(misses))
    if false_pos:
        print("False positives on safe cases:", ", ".join(false_pos))

    if write_json:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / "accuracy.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote {RESULTS_DIR / 'accuracy.json'}")

    # Exit non-zero if the corpus is not perfectly classified, so CI can gate.
    return 0 if not misses and not false_pos else 1


if __name__ == "__main__":
    sys.exit(main(write_json="--json" in sys.argv))
