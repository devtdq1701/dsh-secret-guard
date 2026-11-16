import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, selfTest, urlDenial } from '../index.js'

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

test('file tools are confined: home default-deny, credential paths, spelling and symlink bypasses', async () => {
  const fake = mkdtempSync(join(tmpdir(), 'secret-guard-home-'))
  const ws = join(fake, 'proj')
  mkdirSync(join(fake, '.aws'), { recursive: true })
  writeFileSync(join(fake, '.aws', 'credentials'), 'x')
  mkdirSync(join(fake, '.config', 'other'), { recursive: true })
  writeFileSync(join(fake, '.bash_history'), 'x')
  mkdirSync(join(fake, '.nvm'), { recursive: true })
  mkdirSync(join(ws, 'sub'), { recursive: true })
  symlinkSync(join(fake, '.aws'), join(ws, 'link'))
  const previous = { home: process.env.HOME, cwd: process.cwd() }
  process.env.HOME = fake
  process.chdir(ws)
  try {
    const ctx = fakeCtx()
    apply(ctx)
    const pre = ctx.handlers['tools/pre-execute']
    const allow = async () => ({ kind: 'allow' })
    const kind = async (name, args) => (await pre({ name, arguments: args }, allow)).kind
    for (const [name, args] of [
      ['read', { file_path: '~/.aws/credentials' }], ['read', { file_path: '~//.aws/credentials' }],
      ['read', { file_path: '~/./.aws/credentials' }], ['read', { file_path: 'link/credentials' }],
      ['read', { file_path: `/proc/self/root${fake}/.aws/credentials` }], ['read', { file_path: '../.bash_history' }],
      ['read', { file_path: `${fake}/.bash_history` }], ['read', { file_path: '~root/.ssh/id_rsa' }],
      ['read', { file_path: `${fake}/.config/other/x` }], ['grep', { pattern: '.', path: fake, include: '.aws/*' }],
      ['glob', { pattern: '.aws/*', path: fake }], ['glob', { pattern: '~/.aw?' }], ['grep', { pattern: 'x', path: '/' }],
      ['write', { file_path: `${fake}/evil` }], ['edit', { file_path: '/etc/hosts' }],
      ['apply_patch', { patch: `*** Begin Patch\n*** Add File: ${fake}/evil\n+x\n*** End Patch` }],
      ['working_directory', { cd: fake }], ['working_directory', { cd: '/' }],
    ]) {
      assert.equal(await kind(name, args), 'deny', `${name} ${JSON.stringify(args)}`)
    }
    for (const [name, args] of [
      ['read', { file_path: 'sub/file.py' }], ['read', { file_path: `${ws}/sub/file.py` }], ['write', { file_path: 'new.py' }],
      ['read', { file_path: '/usr/lib/os-release' }], ['read', { file_path: `${fake}/.nvm/x` }],
      ['grep', { pattern: 'x' }], ['glob', { pattern: '**/*.py' }], ['working_directory', { cd: 'sub' }],
      ['bash', { command: 'cat ~/.aws/credentials' }], // bash is confined by the bwrap sandbox, not here
    ]) {
      assert.equal(await kind(name, args), 'allow', `${name} ${JSON.stringify(args)}`)
    }
  } finally {
    process.env.HOME = previous.home
    process.chdir(previous.cwd)
  }
})

test('web_fetch denies IPv4-embedding IPv6 forms, trailing-dot internal names and unresolvable hosts', async () => {
  for (const url of ['http://[::ffff:127.0.0.1]/', 'http://[::ffff:10.0.0.5]/', 'http://[::ffff:169.254.169.254]/',
    'http://[::127.0.0.1]/', 'http://[64:ff9b::7f00:1]/', 'http://[2002:7f00:1::]/', 'http://[2001:0:4136::1]/',
    'http://[fe80::1]/', 'http://[fd00::1]/', 'http://metadata.google.internal./', 'http://x.corp./',
    'http://intranet/', 'http://2130706433/', 'http://127.1/', 'http://no-such-host.invalid/']) {
    assert.ok(await urlDenial(url), url)
  }
  assert.equal(await urlDenial('https://[2606:4700:4700::1111]/'), undefined)
})

test('a gate error reported as a bare systemMessage withholds the output', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'secret-guard-gate-'))
  const gate = join(dir, 'gate.py')
  writeFileSync(gate, `import json, sys\nd = json.load(sys.stdin)\ntext = json.dumps(d)\nif "Q7Q7" in text:\n    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": [t.replace("Q7", "") if t else t for t in d["tool_response"]]}}))\nelif d.get("hook_event_name") == "PostToolUse":\n    print(json.dumps({"systemMessage": "gate failed"}))\n`)
  const ctx = fakeCtx()
  apply(ctx, { gatePath: gate })
  const post = ctx.handlers['tools/post-execute']
  const out = await post({ name: 'bash' }, { content: [{ type: 'text', text: 'anything' }] }, async () => ({ kind: 'accept' }))
  assert.match(out.content[0].text, /withheld/)
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
