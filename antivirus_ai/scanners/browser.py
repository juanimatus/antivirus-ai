"""Revisa extensiones del navegador.

Las extensiones con permiso para leer cookies en todos los sitios pueden
robar la sesión de claude.ai (o de Make, n8n, Gmail...) y usarla desde otro
equipo sin necesitar tu contraseña. Es la causa más típica de compras o
acciones "que no hiciste" sin que hayan cambiado tu clave.
"""

import json
import os
import platform
import zipfile
from pathlib import Path

from ..findings import Finding

ALL_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
SENSITIVE_HOST_HINTS = ("claude.ai", "anthropic.com", "make.com", "n8n", "google.com", "stripe.com")
DANGEROUS_PERMS = {"debugger", "nativeMessaging", "management", "proxy", "webRequestBlocking", "clipboardRead"}


def chromium_profile_roots():
    home = Path.home()
    system = platform.system()
    if system == "Darwin":
        base = home / "Library/Application Support"
        names = ["Google/Chrome", "Chromium", "Microsoft Edge", "BraveSoftware/Brave-Browser", "Arc/User Data"]
    elif system == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        names = ["Google/Chrome/User Data", "Chromium/User Data", "Microsoft/Edge/User Data",
                 "BraveSoftware/Brave-Browser/User Data"]
    else:
        base = home / ".config"
        names = ["google-chrome", "chromium", "microsoft-edge", "BraveSoftware/Brave-Browser"]
    return [(n.split("/")[0], base / n) for n in names if (base / n).is_dir()]


def firefox_profile_roots():
    home = Path.home()
    system = platform.system()
    if system == "Darwin":
        root = home / "Library/Application Support/Firefox/Profiles"
    elif system == "Windows":
        root = Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Mozilla/Firefox/Profiles"
    else:
        root = home / ".mozilla/firefox"
    return [root] if root.is_dir() else []


def _resolve_name(name, ext_dir: Path):
    if not name.startswith("__MSG_"):
        return name
    key = name[6:-2]
    for loc in ("en", "en_US", "es", "es_419"):
        f = ext_dir / "_locales" / loc / "messages.json"
        if f.is_file():
            try:
                msgs = json.loads(f.read_text(encoding="utf-8-sig"))
                for k, v in msgs.items():
                    if k.lower() == key.lower():
                        return v.get("message", name)
            except (OSError, ValueError):
                pass
    return name


def assess_manifest(manifest, name, location):
    perms = set(manifest.get("permissions", [])) | set(manifest.get("optional_permissions", []))
    hosts = set(manifest.get("host_permissions", [])) | {p for p in perms if "://" in p or p == "<all_urls>"}
    for cs in manifest.get("content_scripts", []) or []:
        hosts |= set(cs.get("matches", []))
    all_sites = bool(hosts & ALL_HOSTS)
    sensitive = [h for h in hosts if any(s in h for s in SENSITIVE_HOST_HINTS)]

    out = []
    if "cookies" in perms and (all_sites or sensitive):
        out.append(Finding("browser", "high", f"Extensión puede leer cookies de sesión: {name}", location,
                           f"permisos: cookies + {'todos los sitios' if all_sites else ', '.join(sensitive)}",
                           "Si no la necesitas o no la instalaste tú, elimínala y cierra sesión en todos lados."))
    elif all_sites and ({"webRequest", "scripting", "tabs"} & perms or manifest.get("content_scripts")):
        out.append(Finding("browser", "medium", f"Extensión con acceso a todas las páginas: {name}", location,
                           "puede leer y modificar el contenido de cualquier web (incluida claude.ai)",
                           "Limita su acceso a 'al hacer clic' en chrome://extensions o elimínala."))
    risky = perms & DANGEROUS_PERMS
    if risky:
        out.append(Finding("browser", "medium", f"Extensión con permisos peligrosos: {name}", location,
                           "permisos: " + ", ".join(sorted(risky)),
                           "Comprueba que es una extensión conocida y de confianza."))
    return out


def scan_chromium():
    findings = []
    for browser, root in chromium_profile_roots():
        for ext_root in root.glob("*/Extensions"):
            profile = ext_root.parent.name
            for ext_id_dir in ext_root.iterdir():
                versions = sorted(p for p in ext_id_dir.iterdir() if p.is_dir()) if ext_id_dir.is_dir() else []
                if not versions:
                    continue
                ext_dir = versions[-1]
                try:
                    manifest = json.loads((ext_dir / "manifest.json").read_text(encoding="utf-8-sig"))
                except (OSError, ValueError):
                    continue
                name = _resolve_name(manifest.get("name", ext_id_dir.name), ext_dir)
                loc = f"{browser} [{profile}] {ext_id_dir.name}"
                findings += assess_manifest(manifest, name, loc)
    return findings


def scan_firefox():
    findings = []
    for root in firefox_profile_roots():
        for xpi in root.glob("*/extensions/*.xpi"):
            try:
                with zipfile.ZipFile(xpi) as z:
                    manifest = json.loads(z.read("manifest.json").decode("utf-8-sig"))
            except (OSError, KeyError, ValueError, zipfile.BadZipFile):
                continue
            name = manifest.get("name", xpi.stem)
            findings += assess_manifest(manifest, name, f"Firefox [{xpi.parent.parent.name}] {xpi.name}")
    return findings


def scan():
    return scan_chromium() + scan_firefox()
