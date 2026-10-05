# antivirus-ai

Escáner de seguridad para quienes trabajan con Claude, Make y n8n. Busca las vías
por las que alguien suele entrar en tus cuentas o usarlas a tu nombre:

| Módulo | Qué revisa |
|---|---|
| `secrets` | Claves de API (Anthropic, OpenAI, GitHub, Google, Meta/WhatsApp, Stripe, AWS, Make, n8n…), claves privadas y URLs de webhooks de Make/n8n en tus archivos. Los valores se muestran censurados. |
| `claude` | Configuración de Claude Code / Claude Desktop: `bypassPermissions`, `Bash(*)`, hooks que se conectan a internet, MCP por `http`, de proveedores desconocidos o con secretos en texto plano. |
| `browser` | Extensiones de Chrome, Edge, Brave, Chromium y Firefox que pueden leer cookies de sesión o todas las páginas. Es la forma típica de robar una sesión de claude.ai sin la contraseña. |
| `make` | Cuenta de Make vía API: escenarios tocados por usuarios que no reconoces, webhooks sin autenticación, webhooks sin escenario y conexiones OAuth sin usar. |
| `checklist` | Pasos manuales para la cuenta de Claude: sesiones, facturación, soporte y correo. Ningún escáner los puede hacer, porque claude.ai no tiene una API pública para eso. |

Solo usa Python 3.9+ y la librería estándar. No necesitas instalar nada.

## Uso

```bash
# Escanear una carpeta y tus archivos de configuración personales
python -m antivirus_ai scan ~/proyectos --home

# Incluir la auditoría de Make (token con scopes de solo lectura)
MAKE_API_TOKEN=... MAKE_ZONE=us2.make.com \
  python -m antivirus_ai scan . --trust-make-user 6750603

# Generar un informe para compartir
python -m antivirus_ai scan ~ --home --html informe.html --json informe.json

# Pasos manuales para la cuenta de Claude
python -m antivirus_ai checklist
```

El comando termina con código 1 si encuentra hallazgos `high` o peores. Puedes cambiar el umbral con `--fail-on`.
Así sirve en CI o en un escenario programado de Make o n8n: si el código no es 0, mandas la alerta.

Usa `--skip secrets|claude|browser|make` para omitir un módulo.

## Tests

```bash
pip install pytest && python -m pytest -q
```
