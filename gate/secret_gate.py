#!/usr/bin/env python3
"""Common secret gate: a Claude Code-compatible hook (stdin JSON -> stdout JSON).

Used by dsh-secret-guard as its default gate, and usable as a Claude Code hook
(PreToolUse / PostToolUse / UserPromptSubmit) on its own.

- PreToolUse: deny tool calls whose arguments contain a credential; deny clearly
  destructive or privilege-escalating shell commands; ask (= deny in headless runs)
  for risky ones and for printing known secret files.
- PostToolUse: replace secret values in tool output with <REDACTED:kind>
  (hookSpecificOutput.updatedToolOutput).
- UserPromptSubmit: block a prompt that contains a credential ([MOCK] in the prompt allows it).

Redaction is pattern-based and best effort: an unknown format, or a secret a model
deliberately transforms, is not caught. It is one layer, not a security boundary.
Python 3.9+, stdlib only.
"""
from __future__ import annotations

import json
import os
import re
import sys

DENY, ASK = "deny", "ask"
REDACTED = "<REDACTED:{}>"

# (name, pattern) — a named group `secret` marks the part to redact; otherwise the whole match.
SECRET_PATTERNS = [
    ("Anthropic API Key", re.compile(r"sk-ant-[a-z0-9]{2,8}-[A-Za-z0-9_-]{40,}")),
    ("OpenAI Project Key", re.compile(r"sk-proj-[A-Za-z0-9_-]{40,}")),
    ("sk- API Key", re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{32,}(?![A-Za-z0-9_-])")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Google OAuth Token", re.compile(r"ya29\.[0-9A-Za-z_-]{20,}")),
    ("GitHub Token", re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})")),
    ("GitLab Token", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("Slack Token", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Stripe Key", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("npm Token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("Hugging Face Token", re.compile(r"hf_[A-Za-z0-9]{34,}")),
    ("AWS Access Key ID", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("Private Key", re.compile(r"-----BEGIN (?:[A-Z]+ )?(?:ENCRYPTED )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Telegram Bot Token", re.compile(r"(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])")),
]

KEYED_SECRET = re.compile(
    r"(?i)(?<![\w.-])(?P<key>[\w.-]*(?:token|secret|pass(?:w(?:or)?d)?|pwd|api[_-]?key|access[_-]?key|private[_-]?key)"
    r"[\w.-]*)[\"']?\s*[:=]\s*(?P<open>[\"']?)(?P<secret>(?![/*$<{%])[^\s\"'`,;<>()\[\]{}]{8,})")
PLAIN_WORD = re.compile(r"[A-Za-z]+(?:[._-][A-Za-z]+)*")


def _keyed_value_looks_secret(match: re.Match) -> bool:
    """Keep code readable: `self.token = config.token` or `max_tokens_per_minute` are not secrets."""
    value = match.group("secret")
    if not match.group("open"):
        is_code = "." in value or "_" in value or match.string[match.end():match.end() + 1] == "("
        return not is_code and bool(re.search(r"\d", value)) and bool(re.search(r"[A-Za-z]", value))
    return bool(re.search(r"passw", match.group("key"), re.I)) or not PLAIN_WORD.fullmatch(value)


REDACT_PATTERNS = [(name, pattern, None) for name, pattern in SECRET_PATTERNS] + [
    ("URL Credentials", re.compile(r"://[^/\s:@'\"]+:(?P<secret>(?!\$)[^/\s@'\"]{4,})@"), None),
    ("Basic/Bearer Auth", re.compile(r"\b(?:Basic|Bearer)\s+(?P<secret>[A-Za-z0-9+/=._-]{16,})"), None),
    ("Keyed Secret", KEYED_SECRET, _keyed_value_looks_secret),
    ("Curl User Credentials",
     re.compile(r"(?:--user|(?<![\w-])-u)[=\s]+[\"']?[^\s:\"'$]+:(?P<secret>(?![$<])[^\s\"']{4,})"), None),
]

PROMPT_MOCK_TAGS = ("[MOCK]", "[ALLOW_MOCK_TOKEN]")


def scan_text(text: str):
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return name
    return None


def scan_value(value):
    if isinstance(value, str):
        return scan_text(value)
    items = value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
    for item in items:
        found = scan_value(item)
        if found:
            return found
    return None


def redact_secrets(text: str) -> tuple[str, list[str]]:
    """Replace secret values in `text` with <REDACTED:kind>; return the text and the kinds found."""
    kinds: list[str] = []
    for name, pattern, accept in REDACT_PATTERNS:
        def replace(match: re.Match, name: str = name, accept=accept, pattern=pattern) -> str:
            if accept and not accept(match):
                return match.group(0)
            kinds.append(name)
            group = "secret" if "secret" in pattern.groupindex else 0
            start, end = match.span(group)
            whole = match.group(0)
            return whole[:start - match.start()] + REDACTED.format(name) + whole[end - match.start():]
        text = pattern.sub(replace, text)
    return text, kinds


def redact_value(value, kinds: list[str]):
    if isinstance(value, str):
        redacted, found = redact_secrets(value)
        kinds.extend(found)
        return redacted
    if isinstance(value, list):
        return [redact_value(item, kinds) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item, kinds) for key, item in value.items()}
    return value


# ---------------------------------------------------------------------------- shell commands

# (verdict, reason, pattern) matched against each simple command (split on ; && || | newlines).
COMMAND_RULES = [
    (DENY, "privilege escalation", re.compile(r"^(?:\S*/)?(?:sudo|su|doas|pkexec|run0)\b")),
    (DENY, "filesystem creation/wipe", re.compile(r"^(?:\S*/)?(?:mkfs(?:\.\w+)?|wipefs|shred)\b")),
    (DENY, "raw write to a device", re.compile(r"^(?:\S*/)?dd\b.*\bof=/dev/(?!null\b)")),
    (DENY, "power state change", re.compile(r"^(?:\S*/)?(?:shutdown|reboot|poweroff|halt)\b")),
    (DENY, "recursive delete of a root, home or parent path",
     re.compile(r"^(?:\S*/)?rm\b(?=.*\s-\w*[rR])(?=.*\s-\w*f).*\s(?:/|/\*|~|~/|~/\*|\$HOME/?|\.\./?|\.\.?/?\*?)\s*$")),
    (DENY, "recursive permission change on a root or home path",
     re.compile(r"^(?:\S*/)?ch(?:mod|own)\b.*\s-\w*R\w*\s.*\s(?:/|~|\$HOME)/?\s*$")),
    (DENY, "piping a download into a shell", re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")),
    (ASK, "force push", re.compile(r"^git\b.*\bpush\b.*(?:\s--force(?!-with-lease)\b|\s-f\b)")),
    (ASK, "discarding work", re.compile(r"^git\b.*\b(?:reset\s+--hard|clean\s+-\w*[fdx])")),
    (ASK, "cluster or infrastructure change",
     re.compile(r"^(?:kubectl|oc)\b.*\b(?:delete|apply|replace|patch|scale|drain|cordon)\b"
                r"|^helm\b.*\b(?:install|upgrade|uninstall|delete|rollback)\b"
                r"|^terraform\b.*\b(?:apply|destroy|import)\b")),
    (ASK, "container cleanup", re.compile(r"^docker\b.*\b(?:system\s+prune|volume\s+(?:rm|prune)|rm\b|rmi\b)")),
    (ASK, "destructive SQL", re.compile(r"(?i)\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b")),
    (ASK, "printing the whole environment", re.compile(r"^(?:env|printenv)\s*$")),
]

SECRET_FILE = re.compile(
    r"(?:^|[\s/'\"=])(?:\.env(?:\.(?!example|sample|template|dist)\w[\w.-]*)?|id_(?:rsa|dsa|ecdsa|ed25519)|"
    r"[\w.-]+\.(?:pem|key|pfx|p12|jks|keystore)|credentials(?:\.json)?|\.netrc|\.git-credentials|\.pgpass)"
    r"(?=$|[\s'\";|&>)])")
FILE_READERS = re.compile(r"^(?:\S*/)?(?:cat|tac|head|tail|less|more|bat|nl|sed|awk|jq|yq|grep|rg|strings|base64|"
                          r"xxd|od|hexdump|diff|cp|scp|rsync)\b")
SPLIT = re.compile(r"\s*(?:;|&&|\|\||\||\n|`|\$\()\s*")


def classify_command(command: str):
    """(verdict, reason) for the riskiest simple command in `command`, or None."""
    ask = None
    for raw in SPLIT.split(command):
        part = raw.strip().lstrip("(").strip()
        if not part:
            continue
        for verdict, reason, pattern in COMMAND_RULES:
            if pattern.search(part) or (reason == "piping a download into a shell" and pattern.search(command)):
                if verdict == DENY:
                    return DENY, reason
                ask = ask or (ASK, reason)
        if FILE_READERS.search(part) and SECRET_FILE.search(part):
            ask = ask or (ASK, "printing a secret file")
    return ask


# ---------------------------------------------------------------------------- hook protocol

COMMAND_TOOLS = {"Bash", "bash", "shell"}
READ_TOOLS = {"Read", "read"}


def pre_tool_use(payload: dict):
    tool, args = payload.get("tool_name", ""), payload.get("tool_input") or {}
    found = scan_value(args)
    if found:
        return _decision(DENY, f"tool arguments contain a credential ({found}); use an environment variable instead")
    if tool in COMMAND_TOOLS and isinstance(args, dict):
        verdict = classify_command(str(args.get("command", "")))
        if verdict:
            return _decision(*verdict)
    if tool in READ_TOOLS and isinstance(args, dict) and SECRET_FILE.search(" " + str(args.get("file_path", ""))):
        return _decision(ASK, "reading a secret file")
    return None


def _decision(verdict: str, reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": verdict,
                                   "permissionDecisionReason": f"[SECRET GATE] {reason}"}}


def post_tool_use(payload: dict):
    kinds: list[str] = []
    updated = redact_value(payload.get("tool_response"), kinds)
    if not kinds:
        return None
    return {
        "systemMessage": f"[SECRET GATE] redacted {len(kinds)} secret(s): {', '.join(sorted(set(kinds)))}",
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": updated,
            "additionalContext": ("[SECRET GATE] Secret values in this tool output were replaced with <REDACTED:...>. "
                                  "Do not try to recover them and never write a placeholder back into a file."),
        },
    }


def user_prompt_submit(payload: dict):
    prompt = payload.get("prompt", "")
    if any(tag in prompt for tag in PROMPT_MOCK_TAGS):
        return None
    found = scan_text(prompt)
    if found:
        return {"decision": "block", "reason": f"[SECRET GATE] the prompt contains a {found}; put it in an "
                                               f"environment variable or a file and refer to that (or add [MOCK])."}
    return None


HANDLERS = {"PreToolUse": pre_tool_use, "PostToolUse": post_tool_use, "UserPromptSubmit": user_prompt_submit}


def main() -> int:
    event = None
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        event = payload.get("hook_event_name")
        handler = HANDLERS.get(event)
        output = handler(payload) if handler else None
    except Exception as error:  # fail closed
        if event == "PostToolUse":
            output = {"systemMessage": f"[SECRET GATE] error while redacting ({type(error).__name__}); output not filtered"}
        else:
            output = _decision(ASK, f"gate error ({type(error).__name__})")
    if output:
        print(json.dumps(output, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
