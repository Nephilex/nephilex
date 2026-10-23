"""Sources, sinks, sanitizers and flow features of the JS/TS taint engine.

Each case is a small vulnerable snippet and, where it applies, the fixed
version of the same code: the vulnerable one must report the CWE, the fixed one
must not. Skips cleanly if the [ast] extra is absent.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

from nephilex.scanners import ast_js  # noqa: E402


def _scan(filename: str, code: str):
    parsers = ast_js._load_parsers()
    lang = ast_js._lang_for("." + filename.rsplit(".", 1)[-1])
    src = code.encode()
    tree = parsers[lang].parse(src)
    return list(ast_js._JsAnalyzer(src, filename, False).run(tree.root_node))


def _cwes(filename: str, code: str) -> set[str]:
    return {c for f in _scan(filename, code) for c in f.cwe}


# (id, filename, vulnerable code, fixed code or None, CWE)
CASES = [
    # --- server sources ----------------------------------------------------------
    (
        "express-query-exec",
        "app.js",
        "const { exec } = require('child_process');\n"
        "app.get('/ping', (req, res) => { exec(`ping -c 1 ${req.query.host}`); });\n",
        "const { execFile } = require('child_process');\n"
        "app.get('/ping', (req, res) => { execFile('ping', ['-c', '1', req.query.host]); });\n",
        "CWE-78",
    ),
    (
        "express-body-destructured-readfile",
        "app.js",
        "const fs = require('fs');\nconst path = require('path');\n"
        "app.post('/f', (req, res) => {\n"
        "  const { name = 'a.txt' } = req.body;\n"
        "  res.send(fs.readFileSync(path.join(__dirname, 'files', name)));\n"
        "});\n",
        "const fs = require('fs');\nconst path = require('path');\n"
        "app.post('/f', (req, res) => {\n"
        "  const { name = 'a.txt' } = req.body;\n"
        "  res.send(fs.readFileSync(path.join(__dirname, 'files', path.basename(name))));\n"
        "});\n",
        "CWE-22",
    ),
    (
        "express-sendfile",
        "app.js",
        "app.get('/d/:file', (req, res) => res.sendFile(req.params.file));\n",
        "app.get('/d/:file', (req, res) => res.sendFile(req.params.file, { root: PUBLIC }));\n",
        "CWE-22",
    ),
    (
        "express-header-ssrf",
        "app.js",
        "const axios = require('axios');\n"
        "app.get('/p', async (req, res) => {\n"
        "  const r = await axios.get(req.headers['x-target']);\n"
        "  res.json(r.data);\n"
        "});\n",
        "const axios = require('axios');\nconst ALLOWED = new Set(['api.example.com']);\n"
        "app.get('/p', async (req, res) => {\n"
        "  const target = req.headers['x-target'];\n"
        "  if (!ALLOWED.has(new URL(target).hostname)) return res.sendStatus(400);\n"
        "  const r = await axios.get(target);\n"
        "  res.json(r.data);\n"
        "});\n",
        "CWE-918",
    ),
    (
        "koa-ctx-body-xss",
        "app.js",
        "router.get('/hi', (ctx) => { ctx.body = `<p>Hello ${ctx.query.name}</p>`; });\n",
        "const escapeHtml = require('escape-html');\n"
        "router.get('/hi', (ctx) => { ctx.body = `<p>Hello ${escapeHtml(ctx.query.name)}</p>`; });\n",
        "CWE-79",
    ),
    (
        "koa-request-body-vm",
        "app.js",
        "const vm = require('vm');\n"
        "router.post('/calc', (ctx) => { ctx.body = vm.runInNewContext(ctx.request.body.expr); });\n",
        "router.post('/calc', (ctx) => { ctx.body = JSON.parse(ctx.request.body.expr); });\n",
        "CWE-95",
    ),
    (
        "next-route-handler-json-ssrf",
        "route.ts",
        "export async function POST(request: Request) {\n"
        "  const { url } = await request.json();\n"
        "  const res = await fetch(url);\n"
        "  return new Response(await res.text());\n"
        "}\n",
        "export async function POST(request: Request) {\n"
        "  const { id } = await request.json();\n"
        "  const res = await fetch(`https://api.example.com/items/${encodeURIComponent(id)}`);\n"
        "  return new Response(await res.text());\n"
        "}\n",
        "CWE-918",
    ),
    (
        "next-nexturl-searchparams",
        "route.ts",
        "import { NextRequest, NextResponse } from 'next/server';\n"
        "export async function GET(request: NextRequest) {\n"
        "  const to = request.nextUrl.searchParams.get('to');\n"
        "  return NextResponse.redirect(to as string);\n"
        "}\n",
        "import { NextRequest, NextResponse } from 'next/server';\n"
        "const ALLOWED = ['/home', '/settings'];\n"
        "export async function GET(request: NextRequest) {\n"
        "  const to = request.nextUrl.searchParams.get('to');\n"
        "  if (!ALLOWED.includes(to!)) return NextResponse.redirect('/home');\n"
        "  return NextResponse.redirect(to!);\n"
        "}\n",
        "CWE-601",
    ),
    (
        "next-page-searchparams-redirect",
        "page.tsx",
        "import { redirect } from 'next/navigation';\n"
        "export default function Page({ searchParams }: { searchParams: { next?: string } }) {\n"
        "  redirect(searchParams.next ?? '/');\n"
        "}\n",
        "import { redirect } from 'next/navigation';\n"
        "export default function Page({ searchParams }: { searchParams: { next?: string } }) {\n"
        "  redirect(`/account?next=${encodeURIComponent(searchParams.next ?? '')}`);\n"
        "}\n",
        "CWE-601",
    ),
    (
        "h3-getquery-readfile",
        "server/api/file.ts",
        "import { readFile } from 'node:fs/promises';\n"
        "export default defineEventHandler(async (event) => {\n"
        "  const { name } = getQuery(event);\n"
        "  return readFile(`./data/${name}`, 'utf8');\n"
        "});\n",
        "import { readFile } from 'node:fs/promises';\nimport path from 'node:path';\n"
        "export default defineEventHandler(async (event) => {\n"
        "  const { name } = getQuery(event);\n"
        "  return readFile(`./data/${path.basename(String(name))}`, 'utf8');\n"
        "});\n",
        "CWE-22",
    ),
    (
        "hono-c-req-html",
        "app.ts",
        "app.get('/hi', (c) => c.html(`<h1>${c.req.query('name')}</h1>`));\n",
        "app.get('/hi', (c) => c.text(`Hello ${c.req.query('name')}`));\n",
        "CWE-79",
    ),
    (
        "fastify-reply-html",
        "app.js",
        "fastify.get('/hi', (request, reply) => {\n"
        "  reply.type('text/html').send('<p>' + request.query.name + '</p>');\n"
        "});\n",
        "fastify.get('/hi', (request, reply) => {\n"
        "  reply.type('application/json').send({ name: request.query.name });\n"
        "});\n",
        "CWE-79",
    ),
    (
        "express-send-default-html",
        "app.js",
        "app.get('/e', (req, res) => res.send('Not found: ' + req.query.q));\n",
        "app.get('/e', (req, res) => res.type('text/plain').send('Not found: ' + req.query.q));\n",
        "CWE-79",
    ),
    (
        "node-http-req-url-end",
        "server.js",
        "http.createServer((req, res) => {\n"
        "  res.setHeader('Content-Type', 'text/html');\n"
        '  res.end(`<a href="${req.url}">here</a>`);\n'
        "});\n",
        "const escapeHtml = require('escape-html');\n"
        "http.createServer((req, res) => {\n"
        "  res.setHeader('Content-Type', 'text/html');\n"
        '  res.end(`<a href="${escapeHtml(req.url)}">here</a>`);\n'
        "});\n",
        "CWE-79",
    ),
    (
        "express-redirect-query",
        "app.js",
        "app.get('/login', (req, res) => res.redirect(req.query.next));\n",
        "app.get('/login', (req, res) => res.redirect('/home?from=' + req.query.next));\n",
        "CWE-601",
    ),
    (
        "template-injection-ejs",
        "app.js",
        "const ejs = require('ejs');\n"
        "app.post('/preview', (req, res) => res.send(ejs.render(req.body.template)));\n",
        "const ejs = require('ejs');\n"
        "app.post('/preview', (req, res) => res.send(ejs.render(TEMPLATE, { name: req.body.name })));\n",
        "CWE-1336",
    ),
    (
        "sql-concat-vs-placeholder",
        "db.js",
        "app.get('/u', async (req, res) => {\n"
        "  await pool.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);\n"
        "});\n",
        "app.get('/u', async (req, res) => {\n"
        "  await pool.query('SELECT * FROM users WHERE name = $1', [req.query.name]);\n"
        "});\n",
        "CWE-89",
    ),
    (
        "sql-tagged-template",
        "db.ts",
        "app.get('/u', async (req, res) => {\n"
        "  await prisma.$queryRawUnsafe(`SELECT * FROM u WHERE id = ${req.params.id}`);\n"
        "});\n",
        "app.get('/u', async (req, res) => {\n"
        "  await prisma.$queryRaw(sql`SELECT * FROM u WHERE id = ${req.params.id}`);\n"
        "});\n",
        "CWE-89",
    ),
    # --- browser sources -------------------------------------------------------------
    (
        "dom-location-hash-innerhtml",
        "ui.js",
        "const msg = decodeURIComponent(location.hash.slice(1));\n"
        "document.getElementById('m').innerHTML = msg;\n",
        "const msg = decodeURIComponent(location.hash.slice(1));\n"
        "document.getElementById('m').innerHTML = DOMPurify.sanitize(msg);\n",
        "CWE-79",
    ),
    (
        "dom-postmessage-eval",
        "ui.js",
        "window.addEventListener('message', (event) => {\n  eval(event.data.code);\n});\n",
        "window.addEventListener('message', (event) => {\n"
        "  if (event.origin !== 'https://app.example.com') return;\n"
        "  eval(event.data.code);\n"
        "});\n",
        "CWE-95",
    ),
    (
        "dom-referrer-location",
        "ui.js",
        "window.location.href = document.referrer;\n",
        "window.location.href = '/back?from=' + encodeURIComponent(document.referrer);\n",
        "CWE-601",
    ),
    (
        "dom-document-write",
        "ui.js",
        "document.write('<b>' + window.name + '</b>');\n",
        "document.write('<b>' + escapeHtml(window.name) + '</b>');\n",
        "CWE-79",
    ),
    (
        "react-dangerously-set",
        "View.tsx",
        "import { useSearchParams } from 'next/navigation';\n"
        "export function View() {\n"
        "  const params = useSearchParams();\n"
        "  return <div dangerouslySetInnerHTML={{ __html: params.get('bio') ?? '' }} />;\n"
        "}\n",
        "import DOMPurify from 'dompurify';\nimport { useSearchParams } from 'next/navigation';\n"
        "export function View() {\n"
        "  const params = useSearchParams();\n"
        "  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(params.get('bio') ?? '') }} />;\n"
        "}\n",
        "CWE-79",
    ),
    (
        "jquery-location-hash",
        "ui.js",
        "$(location.hash).show();\n",
        "$(document.getElementById(location.hash.slice(1))).show();\n",
        "CWE-79",
    ),
    # --- archive entries (zip slip) --------------------------------------------------
    (
        "tar-stream-entry",
        "extract.js",
        "const fs = require('fs');\nconst path = require('path');\n"
        "extract.on('entry', (header, stream, next) => {\n"
        "  stream.pipe(fs.createWriteStream(path.join(dest, header.name)));\n"
        "});\n",
        "const fs = require('fs');\nconst path = require('path');\n"
        "extract.on('entry', (header, stream, next) => {\n"
        "  const target = path.resolve(dest, header.name);\n"
        "  if (!target.startsWith(path.resolve(dest) + path.sep)) return next();\n"
        "  stream.pipe(fs.createWriteStream(target));\n"
        "});\n",
        "CWE-22",
    ),
    (
        "adm-zip-entries",
        "unzip.js",
        "const fs = require('fs');\n"
        "for (const entry of zip.getEntries()) {\n"
        "  fs.writeFileSync(dest + '/' + entry.entryName, entry.getData());\n"
        "}\n",
        "const fs = require('fs');\nconst path = require('path');\n"
        "for (const entry of zip.getEntries()) {\n"
        "  fs.writeFileSync(path.join(dest, path.basename(entry.entryName)), entry.getData());\n"
        "}\n",
        "CWE-22",
    ),
    # --- library API heuristic (function parameters) ---------------------------------
    (
        "param-built-shell-command",
        "lib.js",
        "const exec = require('child_process').exec;\n"
        "exports.macAddress = function (nic, cb) {\n"
        "  exec('cat /sys/class/net/' + nic + '/address', cb);\n"
        "};\n",
        "const exec = require('child_process').exec;\n"
        "exports.macAddress = function (nic, cb) {\n"
        "  if (!/^[\\w.-]+$/.test(nic)) throw new Error('bad nic');\n"
        "  exec('cat /sys/class/net/' + nic + '/address', cb);\n"
        "};\n",
        "CWE-78",
    ),
    (
        "param-validator-statement",
        "lib.ts",
        "import { execSync } from 'node:child_process';\n"
        "export function disk(dev: string) {\n"
        "  return execSync(`lsblk -o NAME /dev/${dev}`).toString();\n"
        "}\n",
        "import { execSync } from 'node:child_process';\n"
        "export function disk(dev: string) {\n"
        "  assertValidDevice(dev);\n"
        "  return execSync(`lsblk -o NAME /dev/${dev}`).toString();\n"
        "}\n",
        "CWE-78",
    ),
    (
        "param-through-helper",
        "lib.js",
        "const { exec } = require('child_process');\n"
        "function run(line, cb) { exec(line, cb); }\n"
        "exports.gateway = function (nic, cb) { run('ip r | grep ' + nic, cb); };\n",
        "const { exec } = require('child_process');\n"
        "function run(line, cb) { exec(line, cb); }\n"
        "exports.gateway = function (nic, cb) { run('ip r | grep ' + shellEscape(nic), cb); };\n",
        "CWE-78",
    ),
    (
        "param-promisified-exec",
        "lib.ts",
        "import { exec } from 'child_process';\nimport { promisify } from 'util';\n"
        "const execAsync: (c: string) => Promise<unknown> = promisify(exec);\n"
        "export class Probe {\n"
        "  private static async trace(destination: string) {\n"
        "    const command = `traceroute -m 30 ${destination}`;\n"
        "    return execAsync(command);\n"
        "  }\n"
        "}\n",
        "import { execFile } from 'child_process';\nimport { promisify } from 'util';\n"
        "const execFileAsync = promisify(execFile);\n"
        "export class Probe {\n"
        "  private static async trace(destination: string) {\n"
        "    return execFileAsync('traceroute', ['-m', '30', destination]);\n"
        "  }\n"
        "}\n",
        "CWE-78",
    ),
    (
        "spawn-shell-true",
        "lib.js",
        "const { spawn } = require('child_process');\n"
        "function open(file) { return spawn('xdg-open', [file], { shell: true }); }\n",
        "const { spawn } = require('child_process');\n"
        "function open(file) { return spawn('xdg-open', [file]); }\n",
        "CWE-78",
    ),
    (
        "spawn-cmd-c",
        "lib.js",
        "const childProcess = require('child_process');\n"
        "function launch(editor, args) {\n"
        "  return childProcess.spawn('cmd.exe', ['/C', editor].concat(args));\n"
        "}\n",
        "const childProcess = require('child_process');\n"
        "function launch(editor, args) { return childProcess.spawn(editor, args); }\n",
        "CWE-78",
    ),
    (
        "param-built-eval",
        "lib.js",
        "var parseJSON = function (s) { return window['eval']('(' + s + ')'); };\n",
        "var parseJSON = function (s) { return JSON.parse(s); };\n",
        "CWE-95",
    ),
    (
        "shell-quote-sanitizer",
        "lib.js",
        "const { execSync } = require('child_process');\n"
        "app.get('/g', (req, res) => execSync('git log ' + req.query.ref));\n",
        "const { execSync } = require('child_process');\nconst { quote } = require('shell-quote');\n"
        "app.get('/g', (req, res) => execSync('git log ' + quote([req.query.ref])));\n",
        "CWE-78",
    ),
    # --- path sanitizers -------------------------------------------------------------
    (
        "path-relative-check",
        "static.ts",
        "import fs from 'node:fs/promises';\nimport path from 'node:path';\n"
        "export const serve = (root: string) => async (req: any, res: any) => {\n"
        "  const file = path.resolve(root, req.url);\n"
        "  res.end(await fs.readFile(file));\n"
        "};\n",
        "import fs from 'node:fs/promises';\nimport path from 'node:path';\n"
        "export const serve = (root: string) => async (req: any, res: any) => {\n"
        "  const file = path.resolve(root, req.url);\n"
        "  const rel = path.relative(root, file);\n"
        "  if (rel.startsWith('..') || path.isAbsolute(rel)) return res.end();\n"
        "  res.end(await fs.readFile(file));\n"
        "};\n",
        "CWE-22",
    ),
    (
        "path-rooted-normalize",
        "static.js",
        "const fs = require('fs');\nconst path = require('path');\n"
        "app.use((req, res) => fs.createReadStream(path.join(root, req.path)).pipe(res));\n",
        "const fs = require('fs');\nconst path = require('path');\n"
        "app.use((req, res) => {\n"
        "  const safe = path.normalize('/' + req.path);\n"
        "  fs.createReadStream(path.join(root, safe)).pipe(res);\n"
        "});\n",
        "CWE-22",
    ),
    (
        "path-regex-replace",
        "app.js",
        "const fs = require('fs');\n"
        "app.get('/r', (req, res) => res.send(fs.readFileSync('reports/' + req.query.id)));\n",
        "const fs = require('fs');\n"
        "app.get('/r', (req, res) => {\n"
        "  const id = req.query.id.replace(/[^\\w-]/g, '');\n"
        "  res.send(fs.readFileSync('reports/' + id));\n"
        "});\n",
        "CWE-22",
    ),
    (
        "upload-original-name",
        "upload.js",
        "const fs = require('fs');\n"
        "app.post('/up', upload.single('f'), (req, res) => {\n"
        "  fs.renameSync(req.file.path, 'uploads/' + req.file.originalname);\n"
        "});\n",
        "const fs = require('fs');\n"
        "app.post('/up', upload.single('f'), (req, res) => {\n"
        "  fs.renameSync(req.file.path, 'uploads/' + req.file.filename);\n"
        "});\n",
        "CWE-22",
    ),
    (
        "path-normalize-prefix-check",
        "files.js",
        "const fs = require('fs');\nconst path = require('path');\n"
        "app.get('/f', (req, res) => {\n"
        "  const p = path.normalize(path.join(BASE, req.query.name));\n"
        "  fs.createReadStream(p).pipe(res);\n"
        "});\n",
        "const fs = require('fs');\nconst path = require('path');\n"
        "app.get('/f', (req, res) => {\n"
        "  const p = path.normalize(path.join(BASE, req.query.name));\n"
        "  if (!p.startsWith(BASE + path.sep)) return res.sendStatus(403);\n"
        "  fs.createReadStream(p).pipe(res);\n"
        "});\n",
        "CWE-22",
    ),
    (
        "express-static-root",
        "app.js",
        "const express = require('express');\n"
        "app.use('/u', (req, res, next) => express.static(req.query.dir)(req, res, next));\n",
        "const express = require('express');\napp.use('/u', express.static('public'));\n",
        "CWE-22",
    ),
    (
        "node-fetch-import",
        "proxy.mjs",
        "import fetch from 'node-fetch';\n"
        "export default async function handler(req, res) {\n"
        "  const r = await fetch(req.body.webhook, { method: 'POST' });\n"
        "  res.status(r.status).end();\n"
        "}\n",
        "import fetch from 'node-fetch';\n"
        "export default async function handler(req, res) {\n"
        "  const r = await fetch('https://hooks.example.com/notify', { method: 'POST' });\n"
        "  res.status(r.status).end();\n"
        "}\n",
        "CWE-918",
    ),
    (
        "node-writehead-location",
        "server.js",
        "http.createServer((req, res) => {\n"
        "  const to = new URL(req.url, 'http://x').searchParams.get('to');\n"
        "  res.writeHead(302, { Location: to });\n  res.end();\n"
        "});\n",
        "http.createServer((req, res) => {\n"
        "  const to = new URL(req.url, 'http://x').searchParams.get('to');\n"
        "  res.writeHead(302, { Location: '/go?to=' + encodeURIComponent(to) });\n  res.end();\n"
        "});\n",
        "CWE-601",
    ),
    (
        "http-request-host-option",
        "proxy.js",
        "const http = require('http');\n"
        "app.get('/p', (req, res) => {\n"
        "  http.request({ host: req.query.host, path: '/status' }, (r) => r.pipe(res)).end();\n"
        "});\n",
        "const http = require('http');\n"
        "app.get('/p', (req, res) => {\n"
        "  http.request({ host: 'status.internal', path: '/' + encodeURIComponent(req.query.p) },"
        " (r) => r.pipe(res)).end();\n"
        "});\n",
        "CWE-918",
    ),
]


@pytest.mark.parametrize(
    ("filename", "vulnerable", "fixed", "cwe"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_vulnerable_and_fixed(filename, vulnerable, fixed, cwe):
    assert cwe in _cwes(filename, vulnerable)
    if fixed is not None:
        assert cwe not in _cwes(filename, fixed)


# --- engine behaviour --------------------------------------------------------------


def test_typescript_assertions_and_optional_chaining():
    code = (
        "app.get('/x', (req: Request, res: any) => {\n"
        "  const host = (req as any)?.query!.host as string;\n"
        "  cp.exec(`nslookup ${host}`);\n"
        "});\n"
    )
    for name in ("a.ts", "a.mts", "a.tsx"):
        assert "CWE-78" in _cwes(name, code), name


def test_object_fields_are_tracked_separately():
    code = (
        "app.get('/x', (req, res) => {\n"
        "  const opts = { label: 'static', target: req.query.t };\n"
        "  const merged = { ...opts, mode: 'r' };\n"
        "  fs.readFileSync(merged.label);\n"
        "  fs.readFileSync(merged.target);\n"
        "});\n"
    )
    lines = {f.location.start_line for f in _scan("a.js", code) if "CWE-22" in f.cwe}
    assert lines == {5}


def test_helper_finding_is_reported_at_the_call_site():
    code = (
        "const { exec } = require('child_process');\n"
        "function run(c) { exec(c); }\n"
        "app.get('/x', (req, res) => {\n"
        "  run('ls ' + req.query.dir);\n"
        "});\n"
    )
    [finding] = [f for f in _scan("a.js", code) if "CWE-78" in f.cwe]
    assert finding.location.start_line == 4
    assert finding.metadata["sink_line"] == 2


def test_helper_with_a_callback_is_followed():
    code = (
        "const { exec } = require('child_process');\n"
        "function run(line) {\n"
        "  return new Promise((resolve, reject) => {\n"
        "    exec(line, (err, out) => (err ? reject(err) : resolve(out)));\n"
        "  });\n"
        "}\n"
        "app.get('/x', async (req, res) => res.send(await run('du -sh ' + req.query.dir)));\n"
    )
    [finding] = [f for f in _scan("a.js", code) if "CWE-78" in f.cwe]
    assert finding.location.start_line == 7
    assert finding.metadata["sink_line"] == 4


def test_param_wrappers_and_runner_names_are_not_reported():
    code = (
        "const { exec, execSync } = require('child_process');\n"
        "function sh(line) { return exec(line); }\n"
        "function runCommand(cmd) { return execSync('bash -lc ' + cmd); }\n"
        "function count(n: number) { return execSync('seq ' + n); }\n"
    )
    assert "CWE-78" not in _cwes("a.ts", code)


def test_param_heuristic_is_medium_confidence():
    code = "const cp = require('child_process');\nfunction f(dir) { cp.execSync('ls ' + dir); }\n"
    [finding] = _scan("a.js", code)
    assert finding.confidence.label == "Medium"
    assert finding.metadata["source_kind"] == "param"


def test_function_constructor_with_parameter_is_not_reported():
    code = "function compile(src) { return new Function('data', 'return ' + src); }\n"
    assert not _scan("a.js", code)


def test_browser_sources_do_not_reach_server_sinks():
    code = "fetch(location.href);\nfs.readFileSync(location.hash);\n"
    assert not _scan("a.js", code)


def test_environment_values_only_reach_sql():
    code = (
        "const { execSync } = require('child_process');\n"
        "execSync('ls ' + process.env.HOME);\n"
        "db.query('SELECT * FROM ' + process.env.TABLE);\n"
    )
    assert _cwes("a.js", code) == {"CWE-89"}


def test_html_escaping_does_not_clear_sql():
    code = (
        "const escapeHtml = require('escape-html');\n"
        "app.get('/u', (req, res) => {\n"
        "  const name = escapeHtml(req.query.name);\n"
        "  res.send('<p>' + name + '</p>');\n"
        '  db.query("SELECT * FROM u WHERE n = \'" + name + "\'");\n'
        "});\n"
    )
    assert _cwes("a.js", code) == {"CWE-89"}


def test_weak_prefix_check_is_reported_and_separator_form_is_not():
    weak = (
        "const path = require('path');\n"
        "function safe(rootDir, p) {\n"
        "  const resolved = path.resolve(rootDir, p);\n"
        "  if (!resolved.startsWith(rootDir)) throw new Error('escape');\n"
        "  return resolved;\n"
        "}\n"
    )
    fixed = weak.replace("startsWith(rootDir)", "startsWith(rootDir + path.sep)")
    assert [f.rule_id for f in _scan("a.js", weak)] == ["ast-js.ast-path-prefix-check"]
    assert not _scan("a.js", fixed)


def test_search_params_append_does_not_make_a_redirect_open():
    code = (
        "app.get('/sso', (req, res) => {\n"
        "  const url = new URL(IDP_LOGIN_URL);\n"
        "  url.searchParams.append('RelayState', req.query.redirect);\n"
        "  res.redirect(url.toString());\n"
        "});\n"
    )
    assert "CWE-601" not in _cwes("a.js", code)


def test_json_and_explicit_types_are_not_html():
    code = (
        "app.get('/a', (req, res) => res.json({ q: req.query.q }));\n"
        "app.get('/b', (req, res) => { res.setHeader('Content-Type', 'application/json');"
        " res.end(JSON.stringify(req.query)); });\n"
    )
    assert "CWE-79" not in _cwes("a.js", code)


def test_url_allowlist_function_clears_ssrf():
    code = (
        "app.get('/p', async (req, res) => {\n"
        "  const target = req.query.url;\n"
        "  if (!isAllowedUrl(target)) return res.sendStatus(403);\n"
        "  res.json(await (await fetch(target)).json());\n"
        "});\n"
    )
    assert "CWE-918" not in _cwes("a.js", code)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            "const nunjucks = require('nunjucks');\nnunjucks.configure('views', { autoescape: false });\n",
            1,
        ),
        (
            "const nunjucks = require('nunjucks');\nnunjucks.configure('views', { autoescape: true });\n",
            0,
        ),
        (
            "import Handlebars from 'handlebars';\nconst t = Handlebars.compile(src, { noEscape: true });\n",
            1,
        ),
        ("import Handlebars from 'handlebars';\nconst t = Handlebars.compile(src);\n", 0),
    ],
)
def test_template_engine_with_escaping_off(code, expected):
    found = [f for f in _scan("a.js", code) if f.rule_id == "ast-js.ast-template-autoescape-off"]
    assert len(found) == expected


def test_koa_same_origin_referrer_check_clears_redirect():
    vulnerable = (
        "function back(ctx) {\n"
        "  const referrer = ctx.get('Referrer');\n"
        "  if (referrer.startsWith('/')) return ctx.redirect(referrer);\n"
        "}\n"
    )
    fixed = (
        "function back(ctx) {\n"
        "  const referrer = ctx.get('Referrer');\n"
        "  const url = new URL(referrer, ctx.href);\n"
        "  if (url.host === ctx.host) return ctx.redirect(referrer);\n"
        "}\n"
    )
    assert "CWE-601" in _cwes("a.js", vulnerable)
    assert "CWE-601" not in _cwes("a.js", fixed)
