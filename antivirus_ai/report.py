import html
import json
import sys
from collections import Counter
from datetime import datetime

from .findings import SEVERITIES, sort_findings

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}
RESET = "\033[0m"
LABEL = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO"}


def summary(findings):
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in SEVERITIES}


def render_text(findings, color=None):
    color = sys.stdout.isatty() if color is None else color
    out = []
    for f in sort_findings(findings):
        tag = LABEL[f.severity]
        tag = f"{COLORS[f.severity]}[{tag}]{RESET}" if color else f"[{tag}]"
        out.append(f"{tag} {f.title}")
        out.append(f"    dónde:   {f.location}")
        if f.detail:
            out.append(f"    detalle: {f.detail}")
        if f.fix:
            out.append(f"    qué hacer: {f.fix}")
    s = summary(findings)
    out.append("")
    out.append("Resumen: " + ", ".join(f"{LABEL[k]} {v}" for k, v in s.items()))
    if not findings:
        out.append("No se encontraron problemas en lo escaneado.")
    return "\n".join(out)


def render_json(findings):
    return json.dumps({
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summary(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }, ensure_ascii=False, indent=2)


def render_html(findings):
    rows = "\n".join(
        f"<tr class='{f.severity}'><td>{LABEL[f.severity]}</td><td>{html.escape(f.scanner)}</td>"
        f"<td><b>{html.escape(f.title)}</b><br><small>{html.escape(f.detail)}</small></td>"
        f"<td><code>{html.escape(f.location)}</code></td><td>{html.escape(f.fix)}</td></tr>"
        for f in sort_findings(findings)
    )
    s = summary(findings)
    chips = " ".join(f"<span class='chip {k}'>{LABEL[k]}: {v}</span>" for k, v in s.items())
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Informe antivirus-ai</title>
<style>
:root{{--bg:#fff;--fg:#1b1b1b;--muted:#666;--line:#e5e5e5}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151515;--fg:#eee;--muted:#999;--line:#333}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px 16px}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid var(--line);padding:8px;vertical-align:top;text-align:left}}
small{{color:var(--muted)}}code{{word-break:break-all}}.chip{{padding:2px 8px;border-radius:10px;margin-right:4px}}
.critical td:first-child,.chip.critical{{background:#b00020;color:#fff}}.high td:first-child,.chip.high{{color:#d32f2f;font-weight:700}}
.medium td:first-child,.chip.medium{{color:#b26a00}}.low td:first-child,.chip.low{{color:#0277bd}}
.wrap{{overflow-x:auto}}
</style></head><body><h1>Informe antivirus-ai</h1>
<p>{datetime.now():%Y-%m-%d %H:%M} — {chips}</p>
<div class="wrap"><table><tr><th>Severidad</th><th>Módulo</th><th>Hallazgo</th><th>Dónde</th><th>Qué hacer</th></tr>
{rows or "<tr><td colspan=5>Sin hallazgos.</td></tr>"}</table></div></body></html>"""
