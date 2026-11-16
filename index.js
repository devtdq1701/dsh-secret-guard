/**
 * dsh-secret-guard: run a Claude Code-compatible secret gate (default: the bundled gate/secret_gate.py)
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
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { isIP } from 'node:net'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'
import { basename, dirname, join, relative, resolve, sep } from 'node:path'

export const name = 'secret-guard'

/** Interface of the default route; destinations routed elsewhere are VPN / cluster / LAN. */
function defaultDev() {
  const out = spawnSync('ip', ['route', 'show', 'default'], { encoding: 'utf8' }).stdout ?? ''
  return out.match(/\bdev (\S+)/)?.[1]
}

/** IP literal -> byte array (4 or 16 bytes), or null when it is not an IP literal. */
export function ipBytes(ip) {
  if (isIP(ip) === 4) return ip.split('.').map(Number)
  if (isIP(ip) !== 6) return null
  let text = ip.toLowerCase().split('%')[0]
  const dotted = text.match(/(\d+\.\d+\.\d+\.\d+)$/)
  let tail = null
  if (dotted) {
    tail = dotted[1].split('.').map(Number)
    text = text.slice(0, -dotted[1].length) + '0:0'
  }
  const [head, rest] = text.split('::')
  const h = head ? head.split(':') : []
  const r = rest === undefined ? null : (rest ? rest.split(':') : [])
  const groups = r === null ? h : [...h, ...Array(Math.max(0, 8 - h.length - r.length)).fill('0'), ...r]
  if (groups.length !== 8) return null
  const bytes = groups.flatMap((g) => { const v = parseInt(g || '0', 16); return [(v >> 8) & 255, v & 255] })
  if (tail) bytes.splice(12, 4, ...tail)
  return bytes
}

function v4NonPublic([a, b, c]) {
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b < 128)
    || (a === 169 && b === 254) || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168)
    || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)
}

/** True unless the address is public unicast. IPv6 forms that embed or tunnel IPv4
 * (mapped, compatible, NAT64, 6to4, Teredo) are judged by — or denied for — that IPv4. */
export function isNonPublicIp(ip) {
  const b = ipBytes(ip)
  if (!b) return true
  if (b.length === 4) return v4NonPublic(b)
  if (b.slice(0, 10).every(x => x === 0) && b[10] === 255 && b[11] === 255) return v4NonPublic(b.slice(12))
  if (b.slice(0, 12).every(x => x === 0)) return true // ::, ::1, IPv4-compatible
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return true // NAT64
  if (b[0] === 0x20 && b[1] === 0x02) return true // 6to4
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0 && b[3] === 0) return true // Teredo
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true // documentation
  return (b[0] & 0xe0) !== 0x20 // only 2000::/3 is global unicast
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
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.+$/, '')
  if (!host || host === 'localhost' || !host.includes('.') && !isIP(host)
    || /\.(local|internal|lan|home|corp|intranet|localdomain|localhost)$/.test(host)) {
    return `${host || '(empty)'} is an internal name`
  }
  let addresses
  try {
    addresses = isIP(host) ? [host] : (await lookup(host, { all: true })).map(entry => entry.address)
  } catch {
    return `${host} does not resolve here` // fail closed: the fetch may resolve differently
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
  // The gate reports its own redaction errors as a bare systemMessage: treat that as a failure.
  if (out && out.systemMessage && !out.hookSpecificOutput) throw new Error(`gate error: ${out.systemMessage}`)
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

/** Credential locations the worker never needs (also denied inside allowed dirs). Normally
 * replaced by `sensitivePaths` from `dsw setup` (deepseek-worker sandbox/hidden-paths.txt). */
export const DEFAULT_SENSITIVE = [
  '~/.ssh', '~/.kube', '~/.aws', '~/.azure', '~/.gnupg', '~/.docker', '~/.claude', '~/.claude.json', '~/.codex',
  '~/.dsh', '~/.gemini', '~/.config/dsw', '~/.config/deepseek-worker', '~/.config/gh', '~/.config/gcloud',
  '~/.config/dsh-crew', '~/.local/share/keyrings', '~/.local/state/dsw', '~/.password-store', '~/.netrc',
  '~/.git-credentials', '~/.npmrc', '~/.pypirc',
]

/** Home paths file tools may READ (toolchains). Everything else under $HOME is denied unless it
 * is inside the workspace. Normally replaced by `homeAllow` from `dsw setup`. */
export const DEFAULT_HOME_ALLOW = [
  '~/.nvm', '~/.local/bin', '~/.local/lib', '~/.local/share/pnpm', '~/.cargo/bin', '~/.rustup', '~/.pyenv',
  '~/go/pkg/mod', '~/.deno', '~/.bun/bin',
]

const expandHome = p => (p === '~' ? homedir() : p.startsWith('~/') ? homedir() + p.slice(1) : p)
const under = (p, root) => p === root || p.startsWith(root.endsWith(sep) ? root : root + sep)

/** realpath of the longest existing prefix, plus the non-existent rest (resolves symlinks). */
export function realish(p) {
  let current = p
  const rest = []
  for (;;) {
    try {
      return join(realpathSync(current), ...rest)
    } catch {
      const parent = dirname(current)
      if (parent === current) return p
      rest.unshift(basename(current))
      current = parent
    }
  }
}

/** Path arguments of dsh file tools, with the access each one needs. */
export function fileToolPaths(exec) {
  const args = exec.arguments ?? {}
  const out = []
  const add = (raw, mode) => { if (typeof raw === 'string' && raw !== '') out.push({ raw, mode }) }
  switch (exec.name) {
    case 'read': case 'read_image': add(args.file_path, 'read'); break
    case 'write': case 'edit': add(args.file_path, 'write'); break
    case 'apply_patch':
      for (const text of argStrings(args)) {
        for (const m of text.matchAll(/^\*\*\* (?:(?:Add|Update|Delete) File|Move to):\s*(.+?)\s*$/gm)) add(m[1], 'write')
      }
      break
    case 'grep': case 'glob': {
      add(args.path ?? '.', 'search')
      const pattern = typeof args.pattern === 'string' ? args.pattern : ''
      if (exec.name === 'glob' && /^[~/]/.test(pattern)) add(pattern.split(/[*?[{]/)[0] || '/', 'search')
      break
    }
    case 'working_directory': add(args.cd, 'cd'); break
    default:
      for (const key of ['file_path', 'path', 'filePath']) add(args[key], 'read')
  }
  return out
}

/** Why a file-tool path is refused, or undefined. `cwd` is the session cwd, `root` the workspace. */
export function pathDenial(entry, { cwd, root, home, allow, sensitive }) {
  const raw = entry.raw
  if (raw.startsWith('~') && raw !== '~' && !raw.startsWith('~/')) return `${raw}: ~user paths are not allowed`
  if (raw.split(/[\\/]+/).includes('..')) return `${raw}: '..' segments are not allowed`
  const lexical = resolve(cwd, expandHome(raw))
  const real = realish(lexical)
  const both = [lexical, real]
  for (const p of both) {
    if (/^\/(proc|sys)(\/|$)/.test(p) || (/^\/dev(\/|$)/.test(p) && p !== '/dev/null')) return `${raw}: ${p} is off limits`
  }
  for (const p of both) {
    const hit = sensitive.find(s => under(p, s))
    if (hit) return `${raw}: ${hit} is a protected credential path`
  }
  const inRoot = both.every(p => under(p, root))
  if (entry.mode === 'write' || entry.mode === 'cd') return inRoot ? undefined : `${raw}: outside the workspace ${root}`
  if (entry.mode === 'search' && both.some(p => under(home, p))) return `${raw}: search root contains the home directory`
  if (inRoot) return undefined
  if (both.some(p => under(p, home)) && !allow.some(a => both.every(p => under(p, a)))) {
    return `${raw}: home paths outside the workspace are not readable`
  }
  return undefined
}

/** Every string inside a tool's arguments (paths, patterns, commands). */
/** A file name as a whole path segment: `settings.ini` matches `a/settings.ini`, not `settings.ini.example`. */
export function namePattern(name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`(^|[\\s/'"\`=(<>:;|&,])${escaped}($|[^\\w.-])`)
}

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
    gate: config.gatePath ?? fileURLToPath(new URL('./gate/secret_gate.py', import.meta.url)),
    python: config.python ?? 'python3',
    timeoutMs: config.timeoutMs ?? 10000,
  }
  if (!existsSync(options.gate)) throw new Error(`secret-guard: gate not found at ${options.gate}`)
  selfTest(options)
  ctx.provide('secretGuard', { gate: options.gate, selfTested: true })
  const gateName = exec => TOOL_NAMES[exec.name] ?? exec.name

  const realHome = realish(homedir())
  const sensitive = (config.sensitivePaths ?? DEFAULT_SENSITIVE).map(p => realish(expandHome(p)))
  const homeAllow = (config.homeAllow ?? DEFAULT_HOME_ALLOW).map(p => realish(expandHome(p)))
  const fixedRoot = config.workspaceRoot ? realish(expandHome(config.workspaceRoot)) : undefined
  const roots = new WeakMap() // agent -> workspace root (its first-seen cwd)
  const tainted = new Set()
  const taintedNames = new Set()

  ctx.get('tools').guard((exec) => {
    const strings = argStrings(exec.arguments)
    // Taint: a file whose output was redacted may not be touched again (blocks slicing/encoding it).
    // Match by file name too: `cd dir && cat name` reaches the same file through another path.
    for (const value of strings) {
      const hit = [...tainted].find(path => value.includes(path))
        ?? [...taintedNames].find(name => namePattern(name).test(value))
      if (hit) {
        return `[SECURITY GATE] ${exec.name} denied: ${hit} holds a redacted secret. This block is intentional: ` +
          'do not access it by any means (other tools, paths, scripts or encodings). Leave that file unchanged, ' +
          'finish the rest of the task, and list it in your final answer as blocked.'
      }
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
      taintedNames.add(basename(absolute))
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
    // dsh file tools run in this node process, outside bwrap: confine them like the sandbox does.
    const entries = fileToolPaths(exec)
    if (entries.length > 0) {
      let cwd = realish(process.cwd())
      try {
        const wd = ctx.get('workingDirectory')
        if (wd && exec.agent) cwd = realish(await wd.ensure(exec.agent, exec.signal))
      } catch {
        return { kind: 'deny', reason: `[SECURITY GATE] ${exec.name} denied: session working directory unavailable` }
      }
      let root = fixedRoot ?? (exec.agent ? roots.get(exec.agent) : undefined)
      if (!root) {
        root = cwd
        if (exec.agent) roots.set(exec.agent, root)
      }
      if (!under(cwd, root)) {
        return { kind: 'deny', reason: `[SECURITY GATE] ${exec.name} denied: session cwd ${cwd} left the workspace ${root}` }
      }
      for (const entry of entries) {
        const denial = pathDenial(entry, { cwd, root, home: realHome, allow: homeAllow, sensitive })
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
