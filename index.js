/**
 * dsh-secret-guard: run the Claude Code security gate (~/.claude/hooks/security-gate.py)
 * on DeepSeek Harness's native tool seams.
 *
 * - tools.guard(): deny a call the gate denies or would ask about (headless has no human).
 * - tools/post-execute: replace secret-bearing text with the gate's redacted text.
 * - tools/ptc-dispatch-log: same redaction for PTC dispatch log copies.
 *
 * Fails closed: a missing gate or a failed startup self-test throws (the plugin does
 * not activate and its `secretGuard` service is absent; inject it into a required
 * entry such as `agent-loop` so startup stops); a gate error at run time denies the
 * call or withholds the output.
 */
import { spawnSync } from 'node:child_process'
import { lookup } from 'node:dns/promises'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { isIP } from 'node:net'
import { homedir } from 'node:os'
import { join, relative, resolve, sep } from 'node:path'

export const name = 'secret-guard'

/** Interface of the default route; destinations routed elsewhere are VPN / cluster / LAN. */
function defaultDev() {
  const out = spawnSync('ip', ['route', 'show', 'default'], { encoding: 'utf8' }).stdout ?? ''
  return out.match(/\bdev (\S+)/)?.[1]
}

/** True for loopback, private, link-local, CGNAT, multicast, reserved and unique-local addresses. */
export function isNonPublicIp(ip) {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b < 128)
      || (a === 169 && b === 254) || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168)
  }
  const v6 = ip.toLowerCase()
  if (v6.startsWith('::ffff:')) return isNonPublicIp(v6.slice(7))
  return v6 === '::' || v6 === '::1' || /^f[cd]/.test(v6) || /^fe[89ab]/.test(v6) || v6.startsWith('ff')
}

/** 'ok' public via default route, 'bad' non-public or routed elsewhere, 'none' unroutable. */
/** IPv4 non-default route prefixes as [network, maskBits]. */
function specificRoutes() {
  const out = spawnSync('ip', ['-4', 'route'], { encoding: 'utf8' }).stdout ?? ''
  return out.split('\n').map(line => line.split(' ')[0]).filter(p => /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(p))
    .map(p => { const [net, bits = '32'] = p.split('/'); return [ipv4ToInt(net), Number(bits)] })
}

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, part) => ((acc << 8) | Number(part)) >>> 0, 0)
}

export function routeClass(ip, dev = defaultDev()) {
  if (isNonPublicIp(ip)) return 'bad'
  if (isIP(ip) === 4) {
    const value = ipv4ToInt(ip)
    const covered = specificRoutes().some(([net, bits]) => {
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
      return ((value & mask) >>> 0) === ((net & mask) >>> 0)
    })
    if (covered) return 'bad' // a specific route (VPN, cluster, office network), even on the default device
  }
  const out = spawnSync('ip', ['route', 'get', ip], { encoding: 'utf8' }).stdout ?? ''
  const found = out.match(/\bdev (\S+)/)?.[1]
  if (!found) return 'none'
  return dev && found === dev ? 'ok' : 'bad'
}

/** Why a URL must not be fetched from this host, or undefined when it may. */
export async function urlDenial(raw) {
  let url
  try {
    url = new URL(raw)
  } catch {
    return undefined // not a URL argument
  }
  if (!/^https?:$/.test(url.protocol)) return `scheme ${url.protocol} not allowed`
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (host === 'localhost' || /\.(local|internal|lan|home|corp|intranet|localdomain)$/.test(host)) {
    return `${host} is an internal name`
  }
  let addresses
  try {
    addresses = isIP(host) ? [host] : (await lookup(host, { all: true })).map(entry => entry.address)
  } catch {
    return undefined // unresolvable: the fetch itself will fail
  }
  const dev = defaultDev()
  const classes = addresses.map(ip => routeClass(ip, dev))
  if (classes.includes('bad')) return `${host} resolves to a private, VPN or cluster address`
  return undefined
}
export const inject = ['tools']

/** dsh tool name -> Claude Code tool name the gate understands. */
const TOOL_NAMES = { bash: 'Bash', read: 'Read', write: 'Write', edit: 'Edit', glob: 'Glob', grep: 'Grep' }
/** The gate exits early when any of these is "1"; never let the worker inherit them. */
const BYPASS_ENV_VARS = ['CLAUDE_GUARD_BYPASS', 'ANTIGRAVITY_GUARD_BYPASS', 'CODEX_GUARD_BYPASS', 'AWF_GUARD_BYPASS']
const WITHHELD = '[SECURITY GATE] tool output withheld: the secret gate could not check it.'

/** Run the gate once; returns its parsed JSON output or null (no output = no finding). */
export function runGate({ gate, python, timeoutMs }, payload) {
  const env = { ...process.env }
  for (const key of BYPASS_ENV_VARS) delete env[key]
  const run = spawnSync(python, [gate], { input: JSON.stringify(payload), encoding: 'utf8', timeout: timeoutMs, env })
  if (run.error) throw run.error
  if (run.status !== 0) throw new Error(`gate exited ${run.status}: ${String(run.stderr).slice(0, 200)}`)
  const out = run.stdout.trim()
  return out ? JSON.parse(out) : null
}

/** Redact every text block; returns null when nothing changed. Throws on gate failure. */
export function redactBlocks(options, toolName, blocks) {
  const texts = blocks.map(block => block.type === 'text' ? block.text : null)
  if (!texts.some(text => typeof text === 'string' && text.length > 0)) return null
  const out = runGate(options, {
    hook_event_name: 'PostToolUse', tool_name: toolName, tool_input: {}, tool_response: texts,
  })
  const updated = out?.hookSpecificOutput?.updatedToolOutput
  if (!Array.isArray(updated)) return null
  return blocks.map((block, index) => block.type === 'text' ? { ...block, text: String(updated[index]) } : block)
}

/** Gate verdict for a call: a denial reason, or undefined to allow. Throws on gate failure. */
export function preVerdict(options, toolName, args) {
  const out = runGate(options, { hook_event_name: 'PreToolUse', tool_name: toolName, tool_input: args ?? {} })
  const spec = out?.hookSpecificOutput
  if (spec?.permissionDecision === 'deny' || spec?.permissionDecision === 'ask') {
    return `[SECURITY GATE] ${spec.permissionDecisionReason ?? 'blocked'}`
  }
  return undefined
}

/** Startup self-test: a canary token in tool output must come back redacted. */
export function selfTest(options) {
  const canary = 'gh' + 'p_' + 'Q7'.repeat(18)
  const redacted = redactBlocks(options, 'Bash', [{ type: 'text', text: `token=${canary}` }])
  if (redacted === null || redacted[0].text.includes(canary)) {
    throw new Error('secret-guard: self-test failed — the gate did not redact a canary token')
  }
}

/** Credential locations the worker never needs; mirrors sandbox/dsw-bwrap in deepseek-worker. */
export const DEFAULT_SENSITIVE = [
  '~/.ssh', '~/.kube', '~/.aws', '~/.gnupg', '~/.docker', '~/.claude', '~/.claude.json', '~/.codex', '~/.dsh',
  '~/.gemini', '~/.config/deepseek-worker', '~/.config/gh', '~/.config/gcloud', '~/.config/dsh-crew',
  '~/.local/share/keyrings', '~/.local/state/dsw', '~/.password-store', '~/.netrc', '~/.git-credentials',
  '~/.npmrc', '~/.pypirc',
]

/** Every string inside a tool's arguments (paths, patterns, commands). */
export function argStrings(value, out = []) {
  if (typeof value === 'string') out.push(value)
  else if (Array.isArray(value)) value.forEach(item => argStrings(item, out))
  else if (value && typeof value === 'object') Object.values(value).forEach(item => argStrings(item, out))
  return out
}

/** Paths a redacted call read from: its path arguments, plus existing files a command names. */
export function candidatePaths(exec, cwd) {
  const found = new Set()
  const add = (raw) => {
    if (typeof raw !== 'string' || raw.length < 2) return
    const absolute = resolve(cwd, raw)
    if (existsSync(absolute) && statSync(absolute).isFile()) {
      found.add(absolute)
      const rel = relative(cwd, absolute)
      if (rel && !rel.startsWith('..')) found.add(rel)
    }
  }
  const args = exec.arguments ?? {}
  for (const key of ['file_path', 'path', 'filePath']) add(args[key])
  if (typeof args.command === 'string') {
    for (const token of args.command.split(/[\s'"`;|&<>()=]+/)) add(token)
  }
  return found
}

export function apply(ctx, config = {}) {
  const options = {
    gate: config.gatePath ?? join(homedir(), '.claude/hooks/security-gate.py'),
    python: config.python ?? 'python3',
    timeoutMs: config.timeoutMs ?? 10000,
  }
  if (!existsSync(options.gate)) throw new Error(`secret-guard: gate not found at ${options.gate}`)
  selfTest(options)
  ctx.provide('secretGuard', { gate: options.gate, selfTested: true })
  const gateName = exec => TOOL_NAMES[exec.name] ?? exec.name

  const sensitive = (config.sensitivePaths ?? DEFAULT_SENSITIVE).map(path => path.replace(/^~(?=\/|$)/, homedir()))
  const tainted = new Set()

  ctx.get('tools').guard((exec) => {
    const strings = argStrings(exec.arguments)
    const cwd = process.cwd()
    // dsh file tools run in this node process, outside bwrap: keep them off credential paths.
    for (const value of strings) {
      const resolved = value.startsWith('~') ? value.replace(/^~/, homedir()) : resolve(cwd, value)
      const hit = sensitive.find(path => resolved === path || resolved.startsWith(path + sep)
        || value.includes(path) || value.includes(path.replace(homedir(), '~')))
      if (hit) return `[SECURITY GATE] ${exec.name} denied: ${hit} is a protected credential path`
    }
    // Taint: a file whose output was redacted may not be touched again (blocks slicing/encoding it).
    for (const value of strings) {
      const hit = [...tainted].find(path => value.includes(path))
      if (hit) return `[SECURITY GATE] ${exec.name} denied: ${hit} holds a redacted secret; work around that file`
    }
    try {
      return preVerdict(options, gateName(exec), exec.arguments)
    } catch (error) {
      return `[SECURITY GATE] call denied: the gate failed (${error?.message ?? error})`
    }
  })

  // Taint only files whose own content holds a secret (a command may name several files).
  const taint = (exec) => {
    const cwd = process.cwd()
    for (const path of candidatePaths(exec, cwd)) {
      const absolute = resolve(cwd, path)
      if (path !== absolute) continue  // check each file once, via its absolute form
      try {
        const text = readFileSync(absolute, 'utf8').slice(0, 2_000_000)
        if (redactBlocks(options, 'Read', [{ type: 'text', text }]) === null) continue
      } catch {
        // unreadable here: taint it anyway, fail closed
      }
      tainted.add(absolute)
      const rel = relative(cwd, absolute)
      if (rel && !rel.startsWith('..')) tainted.add(rel)
    }
  }

  // web_fetch runs in this node process, outside bwrap's empty network namespace:
  // keep it off internal, VPN and cluster destinations.
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec.name === 'web_fetch' || exec.name === 'read_url') {
      for (const value of argStrings(exec.arguments)) {
        const denial = await urlDenial(value)
        if (denial) return { kind: 'deny', reason: `[SECURITY GATE] ${exec.name} denied: ${denial}` }
      }
    }
    return next()
  }, { prepend: true })

  const redactOrWithhold = (toolName, blocks) => {
    try {
      return redactBlocks(options, toolName, blocks)
    } catch (error) {
      ctx.logger.warn(`secret-guard: gate failed on ${toolName} output: ${error?.message ?? error}`)
      return [{ type: 'text', text: WITHHELD }]
    }
  }

  ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next()
    const toolName = gateName(exec)
    if (decision.kind === 'block') {
      const feedback = redactOrWithhold(toolName, decision.feedback)
      return feedback === null ? decision : { ...decision, feedback }
    }
    if (Object.hasOwn(decision, 'value')) return decision // execution-local PTC value; its printed form is redacted below
    const content = redactOrWithhold(toolName, decision.content ?? result.content)
    if (content === null) return decision
    taint(exec)
    return { kind: 'accept', content, ...decision.additionalContexts ? { additionalContexts: decision.additionalContexts } : {} }
  }, { prepend: true })

  ctx.on('tools/ptc-dispatch-log', async (dispatch, next) => {
    const content = await next()
    return redactOrWithhold(gateName(dispatch.exec ?? dispatch), content) ?? content
  }, { prepend: true })
}
