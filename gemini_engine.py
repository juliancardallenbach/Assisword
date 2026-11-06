"""Motor Gemini del servidor comercial: soporta claves AI Studio / Vertex, Prompt Libre + Diseño Visual Word y Modo NotebookLM."""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import certifi
import httpx

os.environ.setdefault("SSL_CERT_FILE", certifi.where())
os.environ.setdefault("REQUESTS_CA_BUNDLE", certifi.where())

from google import genai
from google.genai import types

try:
    from google.genai._gaos.utils import BackoffStrategy, RetryConfig
except ImportError:
    BackoffStrategy = None  # type: ignore
    RetryConfig = None  # type: ignore

# Cascada rápida para ortografía y redacción estándar
STANDARD_MODEL_CASCADE: List[Tuple[str, Optional[str]]] = [
    ("gemini-3.5-flash-lite", "minimal"),
    ("gemini-3.1-flash-lite", None),
    ("gemini-3.6-flash", "minimal"),
    ("gemini-3.8-flash", "low"),
]

# Cascada de mayor razonamiento para Prompt Libre Pro (garantiza tildes RAE + estilo + diseño visual simultáneamente)
CUSTOM_PRO_MODEL_CASCADE: List[Tuple[str, Optional[str]]] = [
    ("gemini-3.6-flash", "low"),
    ("gemini-3.8-flash", "low"),
    ("gemini-3.5-flash-lite", "low"),
    ("gemini-3.1-flash-lite", None),
]

FAST_COUNT = 3

UNARY_TIMEOUT = httpx.Timeout(connect=8.0, read=85.0, write=15.0, pool=10.0)
PROBE_TIMEOUT = httpx.Timeout(connect=6.0, read=10.0, write=10.0, pool=6.0)

CORRECTION_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "description": "Lista con cada bloque procesado manteniendo exactamente el mismo id.",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "text": {"type": "string"},
                },
                "required": ["id", "text"],
            },
        }
    },
    "required": ["items"],
}

CUSTOM_VISUAL_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "description": "Lista completa de todos los bloques manteniendo exactamente cada id de entrada.",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "text": {
                        "type": "string",
                        "description": (
                            "Texto final con ortografía, tildes y puntuación RAE 100% corregidas. "
                            "Puede incluir etiquetas inline: <b>...</b>, <i>...</i>, <u>...</u>, "
                            "<c hex='#RRGGBB'>texto en color</c> y <bg hex='#RRGGBB'>resaltado pastel</bg>."
                        ),
                    },
                    "style": {
                        "type": "object",
                        "description": (
                            "Estilo visual opcional del párrafo en Word. Usalo cuando el usuario pida colores, "
                            "formato visual, estética escolar/infantil, ejecutiva, recuadros, resaltados o tipografía."
                        ),
                        "properties": {
                            "role": {
                                "type": "string",
                                "enum": ["normal", "title", "subtitle", "callout", "list_item"],
                            },
                            "font_name": {
                                "type": "string",
                                "description": "Fuente estándar de Windows (ej. 'Comic Sans MS', 'Trebuchet MS', 'Verdana', 'Segoe UI', 'Calibri', 'Georgia', 'Garamond').",
                            },
                            "size_pt": {
                                "type": "number",
                                "description": "Tamaño de letra en puntos (ej. 18 a 22 título, 14 a 16 subtítulo, 11 a 13 cuerpo).",
                            },
                            "bold": {"type": "boolean"},
                            "italic": {"type": "boolean"},
                            "align": {
                                "type": "string",
                                "enum": ["left", "center", "right", "justify"],
                            },
                            "text_color": {
                                "type": "string",
                                "description": "Color base del texto en hexadecimal #RRGGBB.",
                            },
                            "box_bg": {
                                "type": "string",
                                "description": "Color de fondo #RRGGBB del párrafo o tarjeta (ej. '#2563EB' con texto '#FFFFFF' para banner de título, o tonos pastel '#FEF9C3', '#EFF6FF', '#ECFDF5', '#FDF2F8', '#F5F3FF' para recuadros).",
                            },
                            "border_style": {
                                "type": "string",
                                "enum": ["none", "left_bar", "box", "bottom_line"],
                            },
                            "border_color": {
                                "type": "string",
                                "description": "Color del borde o barra lateral en #RRGGBB.",
                            },
                        },
                    },
                },
                "required": ["id", "text"],
            },
        }
    },
    "required": ["items"],
}

BASE_FORMAT_RULES = """REGLAS DE ESTRUCTURA DE WORD (OBLIGATORIAS):
- Recibirás un objeto JSON con una lista "items", donde cada elemento tiene "id" (entero) y "text" (cadena).
- Debés devolver TODOS los "id" de entrada en "items", sin fusionar ni eliminar bloques, para no desfasar las imágenes ni tablas del documento Word.
- Si un bloque incluye etiquetas de formato como <b>...</b>, <i>...</i> o <u>...</u>, mantenelas rodeando las palabras equivalentes. Si un bloque NO tiene etiquetas HTML, NO agregues etiquetas nuevas.
- Conservá numeraciones o viñetas iniciales si el bloque empieza con ellas (ej. "1)", "a)", "•", "-")."""

CUSTOM_FORMAT_AND_VISUAL_RULES = """REGLAS DE ESTRUCTURA Y MOTOR DE DISEÑO VISUAL EN WORD (OBLIGATORIAS):
1. CONSERVACIÓN DE BLOQUES ("id"):
   - Devolvé TODOS los "id" recibidos en "items", uno por uno, sin fusionar ni omitir ninguno, para que las fotos y tablas originales del documento Word permanezcan en su lugar exacto.

2. REGLA INNEGOCIABLE Nº 1 — ORTOGRAFÍA, TILDES Y PUNTUACIÓN RAE AL 100 %:
   - SIEMPRE, además de cumplir el prompt del usuario, debés revisar palabra por palabra y corregir el 100 % de los errores de ortografía (b/v, c/s/z, g/j, h, ll/y), TODAS las tildes y acentos gráficos (agudas, graves, esdrújulas, hiatos acentuales como "había", "día", "actúa", "país", "frío", "río", y tildes diacríticas como "más", "tú", "él", "sí", "sé", "qué", "quién", "cómo", "cuándo", "dónde", "cuánto"), signos de apertura "¿" y "¡", comas, puntos, mayúsculas y concordancia gramatical.
   - Verificá cada oración final antes de responder: NO puede quedar ni una sola falta de tilde ni de ortografía.

3. MOTOR DE FORMATO VISUAL Y COLORES EN WORD ("style" + etiquetas inline):
   - Etiquetas inline permitidas dentro de "text" (solo estas, bien cerradas):
     * <b>texto en negrita</b>
     * <i>texto en cursiva</i>
     * <u>texto subrayado</u>
     * <c hex="#RRGGBB">palabras en color</c>
     * <bg hex="#RRGGBB">frase resaltada con fondo pastel suave</bg>
   - ¿Cuándo aplicar colores y diseño visual ("style" + <c> + <bg>)?
     * SI el usuario pide colores, formato visual, diseño atractivo, estética para niños o escuela, resaltados, cuadros/tarjetas, tipografía o presentación visual:
       APLICÁ UN DISEÑO VISUAL RICO, COHERENTE Y ATRACTIVO en todo el documento usando tanto el objeto "style" de cada bloque como etiquetas inline <b>, <c hex="..."> y <bg hex="...">:
       - Íconos nítidos compatibles con Word y PDF: usá símbolos tipográficos vectoriales limpios que toman el color exacto de la fuente (★, ✦, ❖, ▸, ➜, ✔, ☀, ◆, ●) en lugar de emojis complejos de WhatsApp, para que se vean vectoriales y a todo color al exportar a PDF en cualquier Windows.
       - Para niños / escuela primaria: usá "font_name": "Comic Sans MS" (o "Trebuchet MS" / "Verdana"), acompañá títulos y recuadros con símbolos alegres en color (★, ✦, ✔, ☀, ▸), diseñá el título principal con "role": "title", "box_bg": "#2563EB" (o "#7C3AED"), "text_color": "#FFFFFF", "size_pt": 20, "bold": true, "align": "center", "border_style": "box", "border_color": "#1D4ED8"; subtítulos con "role": "subtitle", "size_pt": 15, "bold": true, "text_color" vivo ("#D97706", "#059669", "#DB2777", "#2563EB") y "border_style": "bottom_line"; párrafos importantes o curiosidades como tarjetas ("role": "callout") alternando fondos pastel suaves ("box_bg": "#FEF9C3" con "border_color": "#F59E0B", "#EFF6FF" con "#3B82F6", "#ECFDF5" con "#10B981", "#FDF2F8" con "#EC4899", usando "border_style": "box" o "left_bar"); y dentro de los párrafos normales ("size_pt": 12.5, "text_color": "#1E293B") destacá palabras clave con <b><c hex="#DC2626">...</c></b>, <b><c hex="#059669">...</c></b>, <b><c hex="#7C3AED">...</c></b> y resaltados suaves <bg hex="#FEF08A">...</bg> o <bg hex="#BAE6FD">...</bg>.
       - Para diseño ejecutivo / profesional / académico con formato visual: usá "font_name": "Segoe UI" o "Calibri" o "Georgia", paleta elegante ("#0F172A", "#1E40AF", "#047857"), subtítulos con "bottom_line", conceptos clave en <b><c hex="#1E40AF">...</c></b> y bloques clave con "role": "callout", "box_bg": "#F8FAFC" o "#EFF6FF", "border_style": "left_bar", "border_color": "#2563EB".
     * SI el usuario SOLO pide cambiar redacción/tono/idioma SIN pedir colores ni diseño visual (ej. "resumilo un poco" o "pasalo a tono formal"): mantené una estética sobria sin colores llamativos (podés usar <b> o <i> donde aporte claridad y omitir "box_bg" / <c> salvo que sea pertinente)."""

PROMPT_ORTOGRAFIA = f"""Sos un corrector ortográfico y tipográfico experto en español (normativa RAE).
Corregí TODOS los errores de ortografía, tildes/acentuación (incluyendo hiatos y tildes diacríticas), signos ¿¡, puntuación, espacios dobles y concordancia evidente.
NO cambies el vocabulario, el estilo personal ni resumas el texto. Conservá cifras, medidas y nombres técnicos intactos.

{BASE_FORMAT_RULES}"""

PROMPT_REDACCION = f"""Sos un editor y corrector de estilo experto en textos en español (normativa RAE).
Corregí absolutamente toda la ortografía, tildes y puntuación, y mejorá la redacción para que cada párrafo se lea claro, fluido, natural y prolijo, manteniendo el 100 % del sentido y datos técnicos del autor.

{BASE_FORMAT_RULES}"""


def build_system_instruction(
    modo: str,
    custom_prompt: str = "",
    has_local_sources: bool = False,
) -> str:
    """Construye en el servidor el prompt maestro (nunca expuesto en el .exe del cliente)."""
    parts: List[str] = []

    custom_clean = (custom_prompt or "").strip()
    if modo == "custom" and custom_clean:
        parts.append(
            "Sos un editor experto en lengua española (RAE), adaptador pedagógico/estilístico y diseñador editorial de documentos Microsoft Word.\n"
            "Debés cumplir SIMULTÁNEAMENTE dos misiones obligatorias sobre cada bloque del documento:\n"
            "  A) Corregir al 100 % toda la ortografía, TODAS las tildes, signos de puntuación y gramática en español (sin excepción).\n"
            "  B) Aplicar de forma completa, fiel y creativa la siguiente INSTRUCCIÓN PERSONALIZADA DEL USUARIO (tanto en redacción/contenido como en colores y formato visual si lo solicita):\n"
            f'"""\n{custom_clean}\n"""'
        )
    elif modo == "redaccion":
        parts.append(PROMPT_REDACCION)
    else:
        parts.append(PROMPT_ORTOGRAFIA)
        if custom_clean:
            parts.append(
                f'Instrucción adicional solicitada por el usuario:\n"""\n{custom_clean}\n"""'
            )

    if has_local_sources:
        parts.append(
            """MODO ESTRICTO DE FUENTES LOCALES (ESTILO NOTEBOOK-LM — CERO INTERNET):
- El usuario adjuntó extractos de sus propios archivos locales de referencia (PDF, PowerPoint, Word, Excel, apuntes).
- REGLA DE ORO: Toda verificación de datos, terminología técnica, nombres propios, fechas, cifras, definiciones o ajustes conceptuales debe basarse EXCLUSIVAMENTE en las FUENTES LOCALES provistas en el mensaje.
- PROHIBIDO usar o inventar información externa que contradiga o no esté respaldada por las fuentes locales del usuario o por el propio texto original.
- Si el texto del documento contiene un dato, término mal escrito, concepto impreciso o cifra que las FUENTES LOCALES aclaran o corrigen, ajustalo con exactitud según las fuentes locales manteniendo coherencia total con ellas."""
        )

    if modo == "custom":
        parts.append(CUSTOM_FORMAT_AND_VISUAL_RULES)

    return "\n\n".join(parts)


def _outbound_transport(retries: int = 1) -> httpx.HTTPTransport:
    """Usa IPv4 directo en Windows hogareño y transporte estándar nativo en Google Cloud Run (Linux)."""
    if sys.platform == "win32" and not os.environ.get("K_SERVICE"):
        return httpx.HTTPTransport(local_address="0.0.0.0", retries=retries, verify=certifi.where())
    return httpx.HTTPTransport(retries=retries, verify=certifi.where())


def _create_client_for_key(
    api_key: str,
    timeout: httpx.Timeout = UNARY_TIMEOUT,
) -> Tuple[genai.Client, httpx.Client, bool]:
    """Crea un cliente hacia Gemini Interactions API compatible con Windows local y Google Cloud Run."""
    httpx_cli = httpx.Client(
        transport=_outbound_transport(retries=1),
        timeout=timeout,
        follow_redirects=True,
    )
    client = genai.Client(
        api_key=api_key,
        http_options={"httpx_client": httpx_cli},
    )
    if RetryConfig is not None and BackoffStrategy is not None:
        try:
            client.interactions.sdk_configuration.retry_config = RetryConfig(
                "attempt-count-backoff",
                BackoffStrategy(300, 1000, 1.5, 1500),
                False,
                max_retries=0,
            )
        except Exception:
            pass
    return client, httpx_cli, False


def _call_model_json(
    client: genai.Client,
    is_vertex: bool,
    model_name: str,
    thinking_level: Optional[str],
    system_instruction: str,
    user_input: str,
    json_schema: Dict[str, Any],
) -> str:
    """Ejecuta una llamada estructurada JSON tanto en AI Studio (Interactions) como en Vertex AI Express."""
    if is_vertex:
        cfg_kwargs: Dict[str, Any] = {
            "system_instruction": system_instruction,
            "response_mime_type": "application/json",
            "response_json_schema": json_schema,
        }
        if thinking_level:
            try:
                cfg_kwargs["thinking_config"] = types.ThinkingConfig(
                    thinking_level=thinking_level.upper()
                )
            except Exception:
                pass
        resp = client.models.generate_content(
            model=model_name,
            contents=user_input,
            config=types.GenerateContentConfig(**cfg_kwargs),
        )
        return (resp.text or "").strip()

    kwargs: Dict[str, Any] = {
        "model": model_name,
        "system_instruction": system_instruction,
        "input": user_input,
        "store": False,
        "response_format": {
            "type": "text",
            "mime_type": "application/json",
            "schema": json_schema,
        },
    }
    if thinking_level:
        kwargs["generation_config"] = {"thinking_level": thinking_level}
    inter = client.interactions.create(**kwargs)
    return (inter.output_text or "").strip()


def test_server_api_keys(primary_key: str, fallback_key: str = "") -> Dict[str, Any]:
    """Diagnostica las claves configuradas en el servidor para mostrar estado claro en /admin."""
    results = []
    for label, key in (("Principal", primary_key), ("Respaldo", fallback_key)):
        clean = (key or "").strip()
        if not clean:
            continue
        tipo = "Google AI Studio (Gemini API)"
        cli, hcli, _ = _create_client_for_key(clean, timeout=PROBE_TIMEOUT)
        t0 = time.time()
        try:
            ok = False
            for mod_test, th_lvl in STANDARD_MODEL_CASCADE[:FAST_COUNT]:
                try:
                    kw = {"model": mod_test, "input": "Respondé únicamente OK", "store": False}
                    if th_lvl:
                        kw["generation_config"] = {"thinking_level": th_lvl}
                    r = cli.interactions.create(**kw)
                    if r and r.output_text:
                        ok = True
                        break
                except Exception as inner_e:
                    if "401" in str(inner_e) or "api_key_invalid" in str(inner_e).lower():
                        raise
            results.append({
                "slot": label,
                "type": tipo,
                "ok": ok,
                "latency_ms": int((time.time() - t0) * 1000),
                "detail": "Conectada y operativa",
            })
        except Exception as exc:
            raw = str(exc)
            hint = raw[:240]
            if "aiplatform.googleapis.com" in raw and "403" in raw:
                hint = (
                    "Falta activar 'Vertex AI API' con 1 clic en tu consola de Google Cloud para ese proyecto "
                    "(ver enlace directo en este panel)."
                )
            results.append({
                "slot": label,
                "type": tipo,
                "ok": False,
                "latency_ms": int((time.time() - t0) * 1000),
                "detail": hint,
            })
        finally:
            hcli.close()
    return {"keys": results, "any_ok": any(r["ok"] for r in results)}


def process_segments_on_server(
    items: List[Dict[str, Any]],
    modo: str,
    custom_prompt: str,
    local_sources_context: str,
    prev_context: List[str],
    primary_key: str,
    fallback_key: str = "",
) -> Dict[int, Dict[str, Any]]:
    """Procesa una tanda de segmentos de Word en el servidor con cascada multimodelo y soporte visual opcional."""
    candidate_keys = [k.strip() for k in (primary_key, fallback_key) if k and k.strip()]
    if not candidate_keys:
        raise RuntimeError("El servidor no tiene una clave GEMINI_API_KEY configurada.")

    is_custom = modo == "custom"
    active_cascade = CUSTOM_PRO_MODEL_CASCADE if is_custom else STANDARD_MODEL_CASCADE
    active_schema = CUSTOM_VISUAL_JSON_SCHEMA if is_custom else CORRECTION_JSON_SCHEMA

    has_sources = bool((local_sources_context or "").strip())
    sys_prompt = build_system_instruction(
        modo=modo,
        custom_prompt=custom_prompt,
        has_local_sources=has_sources,
    )

    prompt_blocks: List[str] = []
    if has_sources:
        prompt_blocks.append(
            "=== FUENTES LOCALES DE REFERENCIA DEL USUARIO (BASE EXCLUSIVA DE VERDAD) ===\n"
            f"{local_sources_context.strip()}\n"
            "=== FIN DE LAS FUENTES LOCALES ===\n"
        )
    if prev_context:
        ctx_str = "\n".join(f"- {t}" for t in prev_context[-2:])
        prompt_blocks.append(
            f"Contexto de párrafos previos (solo referencia, NO incluir en la salida):\n{ctx_str}\n"
        )

    json_payload = json.dumps({"items": items}, ensure_ascii=False)
    extra_reminder = (
        " (Recordá: 100 % de tildes y ortografía RAE corregidas + aplicá todas las instrucciones de contenido y diseño visual/colores solicitadas)"
        if is_custom
        else ""
    )
    prompt_blocks.append(
        f"Procesá los siguientes bloques del documento Word{extra_reminder} y devolvé el JSON completo con todos sus 'id':\n"
        + json_payload
    )
    full_user_input = "\n".join(prompt_blocks)

    fast_indices = list(range(min(FAST_COUNT, len(active_cascade))))
    tail_indices = list(range(min(FAST_COUNT, len(active_cascade)), len(active_cascade)))
    attempt_plan = fast_indices + fast_indices + tail_indices

    last_exc: Optional[Exception] = None

    for key in candidate_keys:
        client, httpx_cli, is_vertex = _create_client_for_key(key, timeout=UNARY_TIMEOUT)
        try:
            for step_num, m_idx in enumerate(attempt_plan):
                model_name, think_lvl = active_cascade[m_idx]
                try:
                    raw_out = _call_model_json(
                        client=client,
                        is_vertex=is_vertex,
                        model_name=model_name,
                        thinking_level=think_lvl,
                        system_instruction=sys_prompt,
                        user_input=full_user_input,
                        json_schema=active_schema,
                    )
                    if not raw_out:
                        raise RuntimeError("Respuesta vacía del modelo.")
                    parsed = json.loads(raw_out)
                    out_items = parsed.get("items", []) if isinstance(parsed, dict) else []
                    mapped: Dict[int, Dict[str, Any]] = {}
                    for entry in out_items:
                        if isinstance(entry, dict) and "id" in entry and "text" in entry:
                            try:
                                seg_id = int(entry["id"])
                                seg_style = entry.get("style")
                                mapped[seg_id] = {
                                    "text": str(entry["text"]),
                                    "style": seg_style if isinstance(seg_style, dict) else None,
                                }
                            except (ValueError, TypeError):
                                continue
                    if not mapped and items:
                        raise RuntimeError("JSON devuelto sin bloques válidos.")
                    return mapped
                except Exception as exc:
                    last_exc = exc
                    err_str = str(exc).lower()
                    if "403" in err_str or "401" in err_str or "api_key_invalid" in err_str or "permission_denied" in err_str:
                        break
                    time.sleep(0.45 if step_num < FAST_COUNT else 1.2)
        finally:
            httpx_cli.close()

    raise RuntimeError(f"No se pudo completar la consulta de IA: {last_exc}")
