"""Audita la configuración local de Claude Code / Claude Desktop.

Busca permisos demasiado amplios, hooks que envían datos a internet,
servidores MCP sin cifrar o desconocidos y claves guardadas en texto plano.
"""

import json
import os
import platform
import re
from pathlib import Path

from ..findings import Finding

EXFIL_RE = re.compile(
    r"(?i)\b(curl|wget|nc|ncat|netcat|Invoke-WebRequest|iwr|scp|ftp)\b|base64\s+-d.*\|\s*(ba)?sh|"
    r"\|\s*(ba)?sh\b|https?://"
)
BROAD_BASH = {"Bash", "Bash(*)", "Bash(:*)"}
RISKY_BASH_PREFIXES = ("Bash(curl", "Bash(wget", "Bash(rm", "Bash(sudo", "Bash(ssh", "Bash(scp", "Bash(nc")
KNOWN_MCP_HOSTS = (
    "anthropic.com", "claude.ai", "github.com", "githubcopilot.com", "make.com",
    "notion.com", "notion.so", "figma.com", "atlassian.com", "linear.app", "slack.com",
    "asana.com", "hubspot.com", "canva.com", "stripe.com", "google.com", "googleapis.com",
)


def candidate_files(project_dirs):
    home = Path.home()
    files = [
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".claude.json",
    ]
    system = platform.system()
    if system == "Darwin":
        files.append(home / "Library/Application Support/Claude/claude_desktop_config.json")
        files.append(Path("/Library/Application Support/ClaudeCode/managed-settings.json"))
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            files.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    else:
        files.append(home / ".config/Claude/claude_desktop_config.json")
        files.append(Path("/etc/claude-code/managed-settings.json"))
    for d in project_dirs:
        d = Path(d).expanduser()
        files += [d / ".claude/settings.json", d / ".claude/settings.local.json", d / ".mcp.json"]
    return [f for f in files if f.is_file()]


def _load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def audit_settings(data, loc):
    out = []
    perms = data.get("permissions") or {}
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode == "bypassPermissions":
        out.append(Finding("claude-config", "high", "Claude Code salta todas las confirmaciones",
                           loc, "permissions.defaultMode = bypassPermissions",
                           "Usa 'default' o 'acceptEdits' salvo en contenedores aislados."))
    for rule in perms.get("allow") or []:
        if rule in BROAD_BASH:
            out.append(Finding("claude-config", "high", "Permiso para ejecutar cualquier comando",
                               loc, f"permissions.allow contiene '{rule}'",
                               "Reemplázalo por comandos concretos, p. ej. 'Bash(npm test:*)'."))
        elif rule.startswith(RISKY_BASH_PREFIXES):
            out.append(Finding("claude-config", "medium", "Permiso automático para un comando sensible",
                               loc, f"permissions.allow contiene '{rule}'",
                               "Quítalo para que Claude pida confirmación antes de usarlo."))
    if data.get("enableAllProjectMcpServers") is True:
        out.append(Finding("claude-config", "medium", "Se aprueban automáticamente los MCP de cualquier repo",
                           loc, "enableAllProjectMcpServers = true",
                           "Ponlo en false: un repo clonado podría traer un MCP malicioso."))
    if data.get("apiKeyHelper"):
        out.append(Finding("claude-config", "info", "Script externo provee la API key",
                           loc, f"apiKeyHelper = {data['apiKeyHelper']}",
                           "Comprueba que ese script es tuyo y no fue modificado."))
    env = data.get("env") or {}
    for k, v in env.items():
        if re.search(r"(?i)(key|token|secret)", k) and isinstance(v, str) and len(v) > 12:
            out.append(Finding("claude-config", "high", "Secreto guardado en texto plano en settings",
                               loc, f"env.{k} tiene un valor literal",
                               "Muévelo al llavero del sistema o usa apiKeyHelper."))
    for event, entries in (data.get("hooks") or {}).items():
        for entry in entries or []:
            for hook in entry.get("hooks", []) if isinstance(entry, dict) else []:
                cmd = hook.get("command", "") if isinstance(hook, dict) else ""
                if cmd and EXFIL_RE.search(cmd):
                    out.append(Finding("claude-config", "high", "Hook que se conecta a internet o ejecuta shell remoto",
                                       loc, f"hooks.{event}: {cmd[:160]}",
                                       "Si no lo escribiste tú, bórralo: un hook corre en cada uso de Claude."))
    return out


def audit_mcp(servers, loc):
    out = []
    for name, cfg in (servers or {}).items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url", "")
        if url:
            if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1)", url):
                out.append(Finding("claude-config", "high", f"MCP '{name}' sin cifrar (http)", loc, url,
                                   "Usa https o elimínalo."))
            elif not any(h in url for h in KNOWN_MCP_HOSTS):
                out.append(Finding("claude-config", "medium", f"MCP remoto '{name}' de origen no verificado", loc, url,
                                   "Confirma que conoces al proveedor; un MCP ve lo que Claude le envía."))
        cmd = " ".join([cfg.get("command", "")] + [str(a) for a in cfg.get("args", [])])
        if EXFIL_RE.search(cmd) and "npx" not in cmd and "uvx" not in cmd:
            out.append(Finding("claude-config", "high", f"MCP '{name}' ejecuta un comando sospechoso", loc, cmd[:160],
                               "Revisa qué hace ese comando antes de seguir usándolo."))
        elif re.search(r"\b(npx|uvx)\b", cmd) and not re.search(r"@\d", cmd):
            out.append(Finding("claude-config", "low", f"MCP '{name}' usa un paquete sin versión fija", loc, cmd[:160],
                               "Fija la versión (paquete@1.2.3) para que no cambie sin que lo sepas."))
        for k, v in (cfg.get("env") or {}).items():
            if re.search(r"(?i)(key|token|secret)", k) and isinstance(v, str) and len(v) > 12 and not v.startswith("${"):
                out.append(Finding("claude-config", "medium", f"MCP '{name}' guarda un secreto en texto plano", loc,
                                   f"env.{k}", "Usa variables de entorno (${VAR}) en lugar del valor literal."))
    return out


def scan(project_dirs=()):
    findings = []
    for path in candidate_files(project_dirs):
        data = _load(path)
        if not isinstance(data, dict):
            continue
        loc = str(path)
        findings += audit_settings(data, loc)
        findings += audit_mcp(data.get("mcpServers"), loc)
        # ~/.claude.json guarda MCPs por proyecto.
        for proj, pdata in (data.get("projects") or {}).items():
            if isinstance(pdata, dict):
                findings += audit_mcp(pdata.get("mcpServers"), f"{loc} [{proj}]")
    return findings
