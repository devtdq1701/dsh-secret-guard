import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, selfTest } from '../index.js'

const TOKEN = 'gh' + 'p_' + 'Zx9'.repeat(12)

function fakeCtx() {
  const handlers = {}
  const guards = []
  const provided = {}
  const warnings = []
  return {
    handlers, guards, provided, warnings,
    provide(name, value) { provided[name] = value; return () => {} },
    get(name) { return name === 'tools' ? { guard: fn => { guards.push(fn); return () => {} } } : undefined },
    on(event, fn) { handlers[event] = fn; return () => {} },
    logger: { warn: message => warnings.push(message) },
  }
}

test('provides the service only after the self-test passes', () => {
  const ctx = fakeCtx()
  apply(ctx)
  assert.equal(ctx.provided.secretGuard.selfTested, true)
  assert.equal(ctx.guards.length, 1)
})

test('missing gate throws so the plugin does not activate', () => {
  assert.throws(() => apply(fakeCtx(), { gatePath: '/nonexistent/gate.py' }), /gate not found/)
})

test('gate that does not redact fails the self-test', () => {
  const dir = mkdtempSync(join(tmpdir(), 'secret-guard-'))
  const noop = join(dir, 'noop_gate.py')
  writeFileSync(noop, 'import sys\nsys.stdin.read()\n')
  assert.throws(() => selfTest({ gate: noop, python: 'python3', timeoutMs: 5000 }), /self-test failed/)
})

test('post-execute replaces secret text and keeps clean output untouched', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const post = ctx.handlers['tools/post-execute']
  const exec = { name: 'bash', arguments: { command: 'cat x' } }
  const dirty = await post(exec, { isError: false, content: [{ type: 'text', text: `deploy_token = ${TOKEN}\n` }] }, async () => ({ kind: 'accept' }))
  assert.equal(dirty.kind, 'accept')
  assert.ok(!dirty.content[0].text.includes(TOKEN))
  assert.match(dirty.content[0].text, /REDACTED/)
  const clean = await post(exec, { isError: false, content: [{ type: 'text', text: 'region = ap-southeast-1' }] }, async () => ({ kind: 'accept' }))
  assert.deepEqual(clean, { kind: 'accept' })
})

test('post-execute redacts block feedback and a replaced projection', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const post = ctx.handlers['tools/post-execute']
  const exec = { name: 'read', arguments: {} }
  const blocked = await post(exec, { content: [] }, async () => ({ kind: 'block', feedback: [{ type: 'text', text: TOKEN }] }))
  assert.ok(!blocked.feedback[0].text.includes(TOKEN))
  const replaced = await post(exec, { content: [] }, async () => ({ kind: 'accept', content: [{ type: 'text', text: TOKEN }] }))
  assert.ok(!replaced.content[0].text.includes(TOKEN))
})

test('gate failure at run time withholds output and denies calls', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const post = ctx.handlers['tools/post-execute']
  const guard = ctx.guards[0]
  const realPath = process.env.PATH
  process.env.PATH = '/nonexistent' // python3 can no longer be found
  try {
    const out = await post({ name: 'bash' }, { content: [{ type: 'text', text: TOKEN }] }, async () => ({ kind: 'accept' }))
    assert.match(out.content[0].text, /withheld/)
    assert.match(guard({ name: 'bash', arguments: { command: 'ls' } }), /gate failed/)
  } finally {
    process.env.PATH = realPath
  }
})

test('guard denies what the gate denies or asks about, allows the rest', () => {
  const ctx = fakeCtx()
  apply(ctx)
  const guard = ctx.guards[0]
  assert.match(guard({ name: 'bash', arguments: { command: 'sudo ls /root' } }), /SECURITY GATE/)
  assert.match(guard({ name: 'bash', arguments: { command: `echo ${TOKEN}` } }), /SECURITY GATE/)
  assert.equal(guard({ name: 'bash', arguments: { command: 'python3 -m unittest' } }), undefined)
  assert.equal(guard({ name: 'read', arguments: { file_path: 'textstats/stats.py' } }), undefined)
})

test('ptc dispatch log copies are redacted', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const log = ctx.handlers['tools/ptc-dispatch-log']
  const out = await log({ name: 'bash', exec: { name: 'bash' } }, async () => [{ type: 'text', text: TOKEN }])
  assert.ok(!out[0].text.includes(TOKEN))
})

test('file tools and commands on credential paths are denied', () => {
  const ctx = fakeCtx()
  apply(ctx)
  const guard = ctx.guards[0]
  assert.match(guard({ name: 'read', arguments: { file_path: '~/.ssh/id_ed25519' } }), /protected credential path/)
  assert.match(guard({ name: 'grep', arguments: { pattern: 'x', path: `${process.env.HOME}/.kube` } }), /protected credential path/)
  assert.match(guard({ name: 'bash', arguments: { command: 'cat ~/.config/deepseek-worker/api_key' } }), /protected credential path/)
  assert.equal(guard({ name: 'read', arguments: { file_path: 'textstats/stats.py' } }), undefined)
})

test('a file whose output was redacted is tainted for later calls', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'secret-guard-taint-'))
  mkdirSync(join(dir, 'config'))
  writeFileSync(join(dir, 'config', 'settings.ini'), `token = ${TOKEN}\n`)
  const previous = process.cwd()
  process.chdir(dir)
  try {
    const ctx = fakeCtx()
    apply(ctx)
    const post = ctx.handlers['tools/post-execute']
    const guard = ctx.guards[0]
    writeFileSync(join(dir, 'clean.py'), 'print(1)\n')
    const read = { name: 'bash', arguments: { command: 'cat clean.py config/settings.ini' } }
    assert.equal(guard(read), undefined)  // first read allowed, its output gets redacted
    await post(read, { content: [{ type: 'text', text: `token = ${TOKEN}` }] }, async () => ({ kind: 'accept' }))
    const slice = { name: 'bash', arguments: { command: "python3 -c \"print(open('config/settings.ini').read()[-4:])\"" } }
    assert.match(guard(slice), /holds a redacted secret/)
    assert.match(guard({ name: 'read', arguments: { file_path: join(dir, 'config/settings.ini') } }), /holds a redacted secret/)
    assert.equal(guard({ name: 'bash', arguments: { command: 'python3 -m unittest' } }), undefined)
    assert.equal(guard({ name: 'edit', arguments: { file_path: 'clean.py' } }), undefined, 'a clean file named in the same command must not be tainted')
  } finally {
    process.chdir(previous)
  }
})

test('web_fetch is denied for internal, private and VPN-routed destinations', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const pre = ctx.handlers['tools/pre-execute']
  const allow = async () => ({ kind: 'allow' })
  for (const url of ['http://127.0.0.1:8080/', 'https://10.1.2.3/x', 'http://192.168.1.1', 'https://localhost/',
    'https://grafana.internal/', 'http://[::1]/', 'file:///etc/passwd']) {
    const decision = await pre({ name: 'web_fetch', arguments: { url } }, allow)
    assert.equal(decision.kind, 'deny', url)
  }
  const publicIp = await pre({ name: 'web_fetch', arguments: { url: 'https://151.101.0.223/' } }, allow)
  assert.equal(publicIp.kind, 'allow')
  const other = await pre({ name: 'bash', arguments: { command: 'curl http://10.0.0.1' } }, allow)
  assert.equal(other.kind, 'allow') // bash has no network in the sandbox; the gate handles it
})
