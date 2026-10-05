import argparse
import os
import sys
from pathlib import Path

from . import __version__, checklist, report
from .findings import SEVERITY_RANK
from .scanners import browser, claude_config, make_audit, secrets


def build_parser():
    p = argparse.ArgumentParser(
        prog="antivirus_ai",
        description="Escáner de seguridad para cuentas de Claude, Make, n8n y tu equipo.",
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Ejecuta los escáneres")
    s.add_argument("paths", nargs="*", default=["."], help="Carpetas/archivos donde buscar secretos (por defecto: .)")
    s.add_argument("--home", action="store_true", help="Incluye ~/.bashrc, ~/.env, ~/.claude.json, etc.")
    s.add_argument("--skip", action="append", default=[], choices=["secrets", "claude", "browser", "make"],
                   help="Omite un módulo (repetible)")
    s.add_argument("--make-zone", default=os.environ.get("MAKE_ZONE", "us2.make.com"))
    s.add_argument("--trust-make-user", type=int, action="append", default=[],
                   help="ID de usuario de Make que reconoces (p. ej. otra cuenta tuya)")
    s.add_argument("--json", metavar="ARCHIVO", help="Guarda el informe en JSON")
    s.add_argument("--html", metavar="ARCHIVO", help="Guarda el informe en HTML")
    s.add_argument("--fail-on", default="high", choices=list(SEVERITY_RANK),
                   help="Código de salida 1 si hay hallazgos de esta severidad o mayor (por defecto: high)")
    s.add_argument("--no-color", action="store_true")

    sub.add_parser("checklist", help="Pasos manuales para asegurar tu cuenta de Claude")
    return p


def run_scan(args):
    findings = []
    if "secrets" not in args.skip:
        findings += secrets.scan_paths(args.paths, include_home=args.home)
    if "claude" not in args.skip:
        findings += claude_config.scan(project_dirs=[p for p in args.paths if Path(p).is_dir()])
    if "browser" not in args.skip:
        findings += browser.scan()
    if "make" not in args.skip:
        token = os.environ.get("MAKE_API_TOKEN")
        if token:
            findings += make_audit.scan(token, args.make_zone, args.trust_make_user)
        else:
            print("· Make: omitido (define MAKE_API_TOKEN para auditar tu cuenta de Make)", file=sys.stderr)

    print(report.render_text(findings, color=False if args.no_color else None))
    if args.json:
        Path(args.json).write_text(report.render_json(findings), encoding="utf-8")
        print(f"JSON guardado en {args.json}")
    if args.html:
        Path(args.html).write_text(report.render_html(findings), encoding="utf-8")
        print(f"HTML guardado en {args.html}")

    threshold = SEVERITY_RANK[args.fail_on]
    return 1 if any(SEVERITY_RANK[f.severity] <= threshold for f in findings) else 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "checklist":
        print(checklist.render_text())
        return 0
    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
