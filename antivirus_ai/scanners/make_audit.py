"""Audita una cuenta de Make.com vía su API.

Requiere un token de API (Make → Perfil → API → Add token) con scopes de
solo lectura: user:read, organizations:read, teams:read, connections:read,
hooks:read, scenarios:read. Variables: MAKE_API_TOKEN y MAKE_ZONE
(p. ej. us2.make.com, eu1.make.com).
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from ..findings import Finding


class MakeClient:
    def __init__(self, token, zone):
        self.base = f"https://{zone}/api/v2"
        self.token = token

    def get(self, path, **params):
        params.setdefault("pg[limit]", 1000)
        url = f"{self.base}{path}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"Authorization": f"Token {self.token}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))


def audit(client, trusted_user_ids=()):
    findings = []
    me = client.get("/users/me")["authUser"]
    trusted = {me["id"], *trusted_user_ids}
    loc = f"Make ({me.get('email')})"

    for org in client.get("/organizations").get("organizations", []):
        org_loc = f"{loc} / org {org['name']}"
        if not org.get("tfaEnforced"):
            findings.append(Finding("make", "low", "La organización no obliga a usar 2FA", org_loc,
                                    "tfaEnforced = false",
                                    "Activa 2FA en tu perfil y, si tienes equipo, oblígalo en la organización."))
        for team in client.get("/teams", organizationId=org["id"]).get("teams", []):
            tloc = f"{org_loc} / team {team['name']}"
            findings += _audit_team(client, team["id"], tloc, trusted)
    return findings


def _audit_team(client, team_id, loc, trusted):
    out = []
    scenarios = client.get("/scenarios", teamId=team_id).get("scenarios", [])
    by_hook = {s.get("hookId"): s for s in scenarios if s.get("hookId")}

    for s in scenarios:
        for role in ("createdByUser", "updatedByUser"):
            user = s.get(role) or {}
            if user.get("id") and user["id"] not in trusted:
                out.append(Finding("make", "high", f"Escenario tocado por un usuario no reconocido: {s['name']}",
                                   loc, f"{role}: {user.get('name')} <{user.get('email')}> (id {user['id']})",
                                   "Si no conoces a ese usuario, desactiva el escenario y revisa los miembros "
                                   "del equipo. Si es tuyo, añádelo con --trust-make-user."))
                break

    for conn in client.get("/connections", teamId=team_id).get("connections", []):
        if not conn.get("scenarioUsages") and conn.get("accountType") == "oauth":
            out.append(Finding("make", "low", f"Conexión sin uso: {conn['name']} ({conn.get('accountLabel')})",
                               loc, "ningún escenario la usa",
                               "Bórrala para reducir superficie de ataque (y revoca el acceso en la app original)."))

    for hook in client.get("/hooks", teamId=team_id).get("hooks", []):
        if hook.get("typeName") != "gateway-webhook":
            continue
        auth = (hook.get("data") or {}).get("authenticationMethod") or {}
        ip = (hook.get("data") or {}).get("ip")
        scen = by_hook.get(hook["id"])
        if not auth.get("apikey") and not ip:
            sev = "medium" if scen and scen.get("isActive") else "low"
            out.append(Finding("make", sev, f"Webhook sin autenticación: {hook['name']}", loc,
                               "cualquiera con la URL puede dispararlo",
                               "Configura API key o restricción por IP en el webhook."))
        if not scen:
            out.append(Finding("make", "low", f"Webhook huérfano: {hook['name']}", loc,
                               "no está asignado a ningún escenario", "Bórralo si no lo usas."))
    return out


def scan(token, zone, trusted_user_ids=()):
    try:
        return audit(MakeClient(token, zone), trusted_user_ids)
    except urllib.error.HTTPError as e:
        return [Finding("make", "info", "No se pudo auditar Make", zone, f"HTTP {e.code}: {e.reason}",
                        "Revisa MAKE_API_TOKEN, MAKE_ZONE y los scopes del token.")]
    except (urllib.error.URLError, TimeoutError) as e:
        return [Finding("make", "info", "No se pudo conectar con Make", zone, str(e), "")]
