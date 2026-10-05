"""Pasos que ningún escáner local puede hacer por ti.

El historial de facturación y las sesiones activas de claude.ai solo se
ven desde la web de Claude; no hay API pública para consultarlos.
"""

CLAUDE_ACCOUNT_STEPS = [
    ("Ahora", "Cierra sesión en todos los dispositivos",
     "claude.ai → Settings → Account → 'Log out of all devices'. Invalida cualquier cookie robada."),
    ("Ahora", "Asegura el correo con el que entras a Claude",
     "El acceso a claude.ai depende de tu email o cuenta de Google: cambia esa contraseña, activa la "
     "verificación en dos pasos y revisa myaccount.google.com/device-activity y /permissions."),
    ("Ahora", "Bloquea o reemplaza la tarjeta usada",
     "Pide al banco que rechace cargos de Anthropic que no reconozcas y considera una tarjeta virtual nueva."),
    ("Hoy", "Revisa facturación y suscripción",
     "claude.ai → Settings → Billing: verifica plan, método de pago e historial de facturas."),
    ("Hoy", "Reporta el incidente a Anthropic",
     "Desde support.anthropic.com (o el chat de ayuda en claude.ai) indica fecha/hora del intento "
     "de compra y pide reembolso de cargos no autorizados."),
    ("Hoy", "Revisa conectores e integraciones de Claude",
     "claude.ai → Settings → Connectors: desconecta lo que no reconozcas (GitHub, Google, Notion, Make…)."),
    ("Hoy", "Rota claves de API de la Console",
     "Si usas console.anthropic.com, revoca claves que no reconozcas y revisa 'Usage' por consumo raro."),
    ("Esta semana", "Escanea tu equipo",
     "Ejecuta 'python -m antivirus_ai scan ~ --home' en tu PC y elimina extensiones del navegador marcadas."),
    ("Esta semana", "Revisa el resto de cuentas conectadas",
     "Make, n8n, GitHub, Meta/WhatsApp: cierra sesiones, revisa tokens y activa 2FA."),
]


def render_text():
    lines = ["", "CHECKLIST MANUAL — cuenta de Claude", "=" * 36]
    for i, (when, title, how) in enumerate(CLAUDE_ACCOUNT_STEPS, 1):
        lines.append(f"[ ] {i}. ({when}) {title}")
        lines.append(f"      {how}")
    return "\n".join(lines)
