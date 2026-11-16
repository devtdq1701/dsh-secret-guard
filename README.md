# dsh-secret-guard

DeepSeek Harness (dsh) plugin that runs `~/.claude/hooks/security-gate.py` on dsh's native tool seams, so DeepSeek workers get the same secret redaction and command gate as Claude Code.

| Seam | Behaviour |
|---|---|
| `tools.guard()` | Deny a call the gate denies or would ask about (headless has no human to ask). |
| `tools/post-execute` | Replace secret text in tool output (and block feedback) with the gate's `<REDACTED:...>` text. |
| `tools/ptc-dispatch-log` | Same redaction for PTC dispatch log copies. |
| `tools/pre-execute` | Deny `web_fetch` / `read_url` to internal names, non-public IPs and any address covered by a specific (VPN, cluster, office) route. |

Fails closed:

- At startup it runs a self-test: a canary token must come back redacted. If the gate is missing or the self-test fails, the plugin throws and its `secretGuard` service is absent.
- Each profile patches the required entry `agent-loop` to inject `secretGuard`, so dsh refuses to start: `startup failed: 1 required plugin did not activate — secret-guard`.
- If the gate fails at run time, the call is denied or its output is withheld.

## Install into a profile

Tested with dsh `0.2.2-rc.3` and Node 24.

```bash
dsh plugin --profile headless add link:$HOME/Workspace/tools/dsh-secret-guard
```

Then put the following in `~/.dsh/profiles/<profile>/cordis.patch.yml`:

```yaml
- insert:
    - id: secret-guard
      name: 'dsh-secret-guard'
      # config: { gatePath, python, timeoutMs }   # defaults: ~/.claude/hooks/security-gate.py, python3, 10000
- id: agent-loop
  inject: [secretGuard]
```

It is installed in the `headless` and `web` profiles. `web` is the dsh-crew hub; restart `dsh web` after changing that profile.

## Verify

```bash
node --test test/*.test.js   # healthy: "# pass 11", "# fail 0"
```

Live checks run on 2026-11-16 against a repo holding a fake GitHub-format token:

- **headless probe:** read + cat of the token file showed 0 raw occurrences in the event stream, and both tool results stayed `completed` with `<REDACTED:GitHub Token>`.
- **full coding task:** visible and hidden tests passed, and the token did not leak.
- **broken `gatePath`:** dsh exited 1 at startup.
- **dsh-crew `dsh_run_worker` (hub):** the session log on disk had 0 raw occurrences and 13 redaction markers.

## Limits

- **Tool name mapping:** dsh tool names are mapped to Claude Code names: bash→Bash, read→Read, write→Write, edit→Edit, glob→Glob, grep→Grep. Other tools are passed under their own names, so the gate only scans their arguments and output for secrets.
- **Cost per call:** each tool call spawns the gate twice (pre and post), about 50–100 ms each.
- **Secret scope:** only secret formats the gate knows are redacted. Proprietary code still goes to DeepSeek.
- **Transformations pass through:** a model that deliberately transforms a secret gets past pattern redaction. In a 2026-11-16 live test, a script printed a token's length and last 4 characters, and that output was not redacted. Keep live credentials out of worker workspaces.
- **Untouched paths:** `additionalContexts` messages added by other plugins, and PTC execution-local `value`s, are not rewritten. Printed output of those values is redacted.
