"""Busca claves de API, tokens y webhooks expuestos en archivos locales.

Una clave filtrada (en un repo, un .env compartido, un blueprint de Make
exportado, un workflow de n8n...) es una de las vías más comunes para que
alguien use tus cuentas o consuma tu saldo.
"""

import os
import re
from pathlib import Path

from ..findings import Finding, redact

# (id, severidad, descripción, regex, cómo arreglarlo)
PATTERNS = [
    ("anthropic-api-key", "critical", "Clave de API de Anthropic (Claude)",
     r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{60,}",
     "Revócala en console.anthropic.com → API Keys y crea una nueva."),
    ("openai-api-key", "critical", "Clave de API de OpenAI",
     r"sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}",
     "Revócala en platform.openai.com → API keys."),
    ("github-token", "critical", "Token de GitHub",
     r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})",
     "Revócalo en github.com → Settings → Developer settings → Tokens."),
    ("aws-access-key", "critical", "Access key de AWS",
     r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
     "Desactívala en la consola IAM de AWS."),
    ("stripe-live-key", "critical", "Clave live de Stripe",
     r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}",
     "Rótala en dashboard.stripe.com → Developers → API keys."),
    ("private-key", "critical", "Clave privada (SSH/TLS)",
     r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
     "Genera un par de claves nuevo y quita la vieja de los servidores."),
    ("google-api-key", "high", "Clave de API de Google",
     r"\bAIza[0-9A-Za-z\-_]{35}\b",
     "Restríngela o elimínala en console.cloud.google.com → Credenciales."),
    ("google-oauth-secret", "high", "Client secret OAuth de Google",
     r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b",
     "Rota el secreto del cliente OAuth en Google Cloud Console."),
    ("meta-access-token", "high", "Token de Meta / WhatsApp Business",
     r"\bEAA[A-Za-z0-9]{90,}",
     "Invalídalo en Meta Business Suite → Usuarios del sistema."),
    ("slack-token", "high", "Token de Slack",
     r"\bxox[abposr]-[A-Za-z0-9\-]{10,}",
     "Revócalo en api.slack.com/apps."),
    ("telegram-bot-token", "high", "Token de bot de Telegram",
     r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b",
     "Pide un token nuevo a @BotFather con /revoke."),
    ("make-api-token", "high", "Token de API de Make",
     r"(?i)(?:make|integromat)[\w\-]{0,20}(?:token|api[_\-]?key)['\"]?\s*[:=]\s*['\"]?"
     r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
     "Bórralo en Make → Perfil → API y crea uno con los scopes mínimos."),
    ("n8n-api-key", "high", "API key de n8n",
     r"(?i)n8n[\w\-]{0,20}(?:api[_\-]?key|token)['\"]?\s*[:=]\s*['\"]?eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
     "Bórrala en n8n → Settings → n8n API."),
    ("make-webhook", "medium", "URL de webhook de Make",
     r"https://hook\.[a-z0-9]+\.make\.com/[a-z0-9]{20,}",
     "Quien tenga la URL puede dispararlo y gastar tus operaciones. "
     "Protégelo con API key (Make → Webhooks → Data structure / API key) o regénéralo."),
    ("n8n-webhook", "medium", "URL de webhook de n8n",
     r"https?://[^\s\"'<>]+/webhook(?:-test)?/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
     "Añade autenticación (Header Auth) al nodo Webhook de n8n."),
    ("generic-secret", "low", "Posible secreto en texto plano",
     r"(?i)\b(?:api[_\-]?key|secret|token|password|passwd|contraseña)\b['\"]?\s*[:=]\s*['\"]([^'\"\s]{16,})['\"]",
     "Muévelo a un gestor de secretos o variable de entorno fuera del repo."),
]

COMPILED = [(pid, sev, desc, re.compile(rx), fix) for pid, sev, desc, rx, fix in PATTERNS]

# Valores de ejemplo típicos que no vale la pena reportar.
PLACEHOLDER_RE = re.compile(r"(?i)(x{6,}|your[_\-]?|example|placeholder|changeme|<[^>]+>|\*{4,}|dummy|test[_\-]?key)")

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".tox", "dist", "build", ".next", ".cache", "site-packages",
    ".idea", ".vscode-server", "Library", "AppData",
}
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".mp3", ".mp4", ".mov", ".woff", ".woff2", ".ttf", ".otf", ".so", ".dll", ".exe",
    ".bin", ".pyc", ".class", ".jar", ".lock", ".sqlite", ".db",
}
MAX_BYTES = 2 * 1024 * 1024

# Archivos de configuración del usuario donde suelen quedar claves sueltas.
HOME_SENSITIVE_FILES = [
    ".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", ".env",
    ".netrc", ".npmrc", ".pypirc", ".claude.json", ".claude/settings.json",
    ".claude/settings.local.json", ".n8n/config", ".config/gh/hosts.yml",
]


def _is_text(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\0" not in fh.read(4096)
    except OSError:
        return False


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in SKIP_EXT:
                continue
            try:
                if p.is_symlink() or p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


def scan_text(text: str, location: str):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        specific_hit = False
        seen_values = set()
        for pid, sev, desc, rx, fix in COMPILED:
            # El patrón genérico va último: solo cuenta si nada más específico saltó.
            if pid == "generic-secret" and specific_hit:
                continue
            for m in rx.finditer(line):
                value = m.group(1) if m.groups() else m.group(0)
                if value in seen_values or PLACEHOLDER_RE.search(value):
                    continue
                seen_values.add(value)
                specific_hit = True
                findings.append(Finding(
                    scanner="secrets",
                    severity=sev,
                    title=desc,
                    location=f"{location}:{lineno}",
                    detail=f"Valor: {redact(value)}",
                    fix=fix,
                    extra={"pattern": pid},
                ))
    return findings


def scan_paths(paths, include_home=False):
    findings = []
    targets = [Path(p).expanduser() for p in paths]
    if include_home:
        home = Path.home()
        targets += [home / f for f in HOME_SENSITIVE_FILES if (home / f).is_file()]
    seen_files = set()
    for target in targets:
        if not target.exists():
            continue
        for f in iter_files(target):
            real = f.resolve()
            if real in seen_files or not _is_text(f):
                continue
            seen_files.add(real)
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            findings.extend(scan_text(text, str(f)))
    return findings
