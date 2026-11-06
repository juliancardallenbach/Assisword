"""Servidor FastAPI comercial de Corrector Pro v2 + Panel de Administrador Web (/admin)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from email_verifier import send_verification_code_email
from gemini_engine import process_segments_on_server, test_server_api_keys
from server_core import server_manager, verify_signed_token

app = FastAPI(
    title="Corrector de Documentos Pro v2 — Servidor Comercial",
    version="2.0.0",
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _client_ip(req: Request) -> str:
    fwd = req.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return req.client.host if req.client else ""


def _extract_bearer(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    parts = authorization.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


def _require_admin(authorization: Optional[str]) -> Dict[str, Any]:
    token = _extract_bearer(authorization)
    claims = verify_signed_token(token)
    if not claims or claims.get("r") != "admin":
        raise HTTPException(status_code=401, detail="Acceso exclusivo para el Administrador.")
    user = server_manager.state.get("users", {}).get(claims["e"])
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=401, detail="Cuenta administradora inválida.")
    return user


# ==============================================================================
# Esquemas Pydantic
# ==============================================================================
class RegisterRequest(BaseModel):
    email: str
    password: str
    display_name: str = ""
    hwid: str = ""


class ResendOtpRequest(BaseModel):
    email: str


class VerifyOtpRequest(BaseModel):
    email: str
    code: str
    hwid: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str
    hwid: str = ""


class SegmentItem(BaseModel):
    id: int
    text: str


class CorrectBatchRequest(BaseModel):
    hwid: str = ""
    modo: str = "ortografia"  # "ortografia" | "redaccion" | "custom"
    custom_prompt: str = ""
    local_sources_context: str = ""
    prev_context: List[str] = Field(default_factory=list)
    items: List[SegmentItem]
    commit_doc: bool = True  # True en el último lote del documento para descontar 1 doc / prueba


class AdminUserActionRequest(BaseModel):
    email: str
    action: str
    monthly_limit: Optional[int] = None


class AdminSettingsRequest(BaseModel):
    settings: Dict[str, Any]


class AdminTestEmailRequest(BaseModel):
    to_email: str


# ==============================================================================
# Rutas públicas y de clientes de escritorio (.exe)
# ==============================================================================
@app.get("/")
def root_redirect():
    return RedirectResponse(url="/admin")


@app.get("/api/health")
@app.get("/api/health/ping")
def health_check():
    return {
        "status": "ok",
        "version": "2.1.0",
        "service_enabled": bool(server_manager.state.get("service_enabled", True)),
    }


@app.post("/api/auth/register")
def api_register(body: RegisterRequest, request: Request):
    ok, code_str, msg = server_manager.register_and_send_otp(
        email=body.email,
        password=body.password,
        display_name=body.display_name,
        hwid=body.hwid,
        ip=_client_ip(request),
    )
    return JSONResponse(
        status_code=200 if ok else 400,
        content={"ok": ok, "status": code_str, "message": msg},
    )


@app.post("/api/auth/resend-otp")
def api_resend_otp(body: ResendOtpRequest, request: Request):
    ok, msg = server_manager.resend_otp(email=body.email, ip=_client_ip(request))
    return JSONResponse(
        status_code=200 if ok else 400,
        content={"ok": ok, "message": msg},
    )


@app.post("/api/auth/verify-otp")
def api_verify_otp(body: VerifyOtpRequest, request: Request):
    ok, msg, data = server_manager.verify_email_otp(
        email=body.email,
        code=body.code,
        hwid=body.hwid,
        ip=_client_ip(request),
    )
    return JSONResponse(
        status_code=200 if ok else 400,
        content={"ok": ok, "message": msg, "data": data},
    )


@app.post("/api/auth/login")
def api_login(body: LoginRequest, request: Request):
    ok, status_str, msg, data = server_manager.login_user(
        email=body.email,
        password=body.password,
        hwid=body.hwid,
        ip=_client_ip(request),
    )
    return JSONResponse(
        status_code=200 if ok else 401 if status_str != "pending_verification" else 403,
        content={"ok": ok, "status": status_str, "message": msg, "data": data},
    )


@app.get("/api/me")
def api_me(
    hwid: str = "",
    authorization: Optional[str] = Header(default=None),
):
    token = _extract_bearer(authorization)
    claims = verify_signed_token(token)
    if not claims:
        raise HTTPException(status_code=401, detail="Sesión inválida o expirada.")
    user = server_manager.state.get("users", {}).get(claims["e"])
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado.")
    return {
        "ok": True,
        "user": server_manager.build_public_user_profile(user, hwid or claims.get("h", "")),
    }


@app.post("/api/correct")
def api_correct_batch(
    body: CorrectBatchRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    token = _extract_bearer(authorization)
    authorized, auth_status, msg, user = server_manager.authorize_correction(
        token=token,
        hwid=body.hwid,
    )
    if not authorized or user is None:
        profile = (
            server_manager.build_public_user_profile(user, body.hwid)
            if user is not None
            else None
        )
        return JSONResponse(
            status_code=402 if auth_status in ("requires_pro", "quota_exceeded") else 403,
            content={
                "ok": False,
                "status": auth_status,
                "message": msg,
                "user": profile,
            },
        )

    if body.modo == "custom" and not (body.custom_prompt or "").strip():
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "status": "bad_request",
                "message": "Escribí tus instrucciones personalizadas en el cuadro de texto antes de corregir.",
            },
        )

    settings = server_manager.state.get("settings", {})
    primary_key = settings.get("gemini_api_key", "")
    fallback_key = settings.get("gemini_fallback_api_key", "")

    raw_items = [{"id": it.id, "text": it.text} for it in body.items]
    try:
        mapped = process_segments_on_server(
            items=raw_items,
            modo=body.modo,
            custom_prompt=body.custom_prompt,
            local_sources_context=body.local_sources_context,
            prev_context=body.prev_context,
            primary_key=primary_key,
            fallback_key=fallback_key,
        )
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={
                "ok": False,
                "status": "ai_error",
                "message": f"El motor inteligente está con alta demanda momentánea. Intentá de nuevo en unos segundos.\n({str(exc)[:180]})",
            },
        )

    chars_count = sum(len(it.text) for it in body.items) + len(body.local_sources_context or "")
    if body.commit_doc:
        updated_profile = server_manager.record_successful_correction(
            user=user,
            auth_mode=auth_status,
            hwid=body.hwid,
            modo=body.modo,
            chars_total=chars_count,
            ip=_client_ip(request),
        )
    else:
        updated_profile = server_manager.build_public_user_profile(user, body.hwid)

    # Serializar salida incluyendo "style" visual cuando exista
    out_list = [
        {
            "id": k,
            "text": v["text"] if isinstance(v, dict) else str(v),
            "style": v.get("style") if isinstance(v, dict) else None,
        }
        for k, v in mapped.items()
    ]
    return {
        "ok": True,
        "status": auth_status,
        "items": out_list,
        "user": updated_profile,
    }


# ==============================================================================
# Panel de Administrador Web (/admin)
# ==============================================================================
@app.get("/admin", response_class=HTMLResponse)
def admin_panel_page():
    html_file = TEMPLATES_DIR / "admin.html"
    return HTMLResponse(content=html_file.read_text(encoding="utf-8"))


@app.get("/api/admin/dashboard")
def api_admin_dashboard(authorization: Optional[str] = Header(default=None)):
    _require_admin(authorization)
    users_list = []
    for email_k, u in server_manager.state.get("users", {}).items():
        server_manager._refresh_user_cycles(u)
        users_list.append({
            "email": email_k,
            "display_name": u.get("display_name", ""),
            "role": u.get("role", "user"),
            "email_verified": bool(u.get("email_verified", False)),
            "plan": u.get("plan", "free"),
            "pro_expires_at": u.get("pro_expires_at"),
            "free_trial_remaining": int(u.get("free_trial_remaining", 0)),
            "docs_used_this_month": int(u.get("docs_used_this_month", 0)),
            "monthly_doc_limit": int(u.get("monthly_doc_limit", 100)),
            "total_docs_corrected": int(u.get("total_docs_corrected", 0)),
            "estimated_cost_usd": round(float(u.get("estimated_cost_usd", 0.0)), 4),
            "devices_count": len(u.get("hwids", [])),
            "max_devices": int(u.get("max_devices", 2)),
            "is_blocked": bool(u.get("is_blocked", False)),
            "created_at": u.get("created_at"),
            "last_login": u.get("last_login"),
        })
    users_list.sort(key=lambda x: (x["role"] != "admin", -(x["created_at"] or 0)))

    s = server_manager.state.get("settings", {})
    safe_settings = {
        "has_primary_key": bool(s.get("gemini_api_key", "").strip()),
        "primary_key_prefix": (s.get("gemini_api_key", "")[:6] + "...") if s.get("gemini_api_key") else "",
        "has_fallback_key": bool(s.get("gemini_fallback_api_key", "").strip()),
        "fallback_key_prefix": (s.get("gemini_fallback_api_key", "")[:6] + "...") if s.get("gemini_fallback_api_key") else "",
        "google_bridge_webhook_url": s.get("google_bridge_webhook_url", ""),
        "smtp_host": s.get("smtp_host", "smtp.gmail.com"),
        "smtp_port": s.get("smtp_port", "465"),
        "smtp_user": s.get("smtp_user", ""),
        "has_smtp_password": bool(s.get("smtp_app_password", "").strip()),
        "smtp_from_name": s.get("smtp_from_name", "Corrector de Documentos Pro"),
        "has_brevo_key": bool(s.get("brevo_api_key", "").strip()),
        "mp_alias": s.get("mp_alias", ""),
        "mp_payment_link": s.get("mp_payment_link", ""),
        "support_whatsapp": s.get("support_whatsapp", ""),
        "pro_price_text": s.get("pro_price_text", "Plan Pro Mensual"),
        "default_monthly_doc_limit": int(server_manager.state.get("default_monthly_doc_limit", 100)),
    }
    return {
        "ok": True,
        "stats": server_manager.state.get("stats", {}),
        "settings": safe_settings,
        "users": users_list,
        "logs": server_manager.state.get("logs", [])[:60],
    }


@app.post("/api/admin/user-action")
def api_admin_user_action(
    body: AdminUserActionRequest,
    authorization: Optional[str] = Header(default=None),
):
    _require_admin(authorization)
    ok, msg = server_manager.admin_update_user_plan(
        target_email=body.email,
        action=body.action,
        monthly_limit=body.monthly_limit,
    )
    return JSONResponse(status_code=200 if ok else 400, content={"ok": ok, "message": msg})


@app.post("/api/admin/settings")
def api_admin_save_settings(
    body: AdminSettingsRequest,
    authorization: Optional[str] = Header(default=None),
):
    _require_admin(authorization)
    server_manager.admin_update_settings(body.settings)
    return {"ok": True, "message": "Configuración guardada correctamente."}


@app.post("/api/admin/test-email")
def api_admin_test_email(
    body: AdminTestEmailRequest,
    authorization: Optional[str] = Header(default=None),
):
    _require_admin(authorization)
    ok, detail = send_verification_code_email(
        to_email=body.to_email.strip(),
        display_name="Prueba Administrador",
        code="123456",
        mail_settings=server_manager.state.get("settings", {}),
    )
    return JSONResponse(status_code=200 if ok else 400, content={"ok": ok, "message": detail})


@app.post("/api/admin/test-keys")
def api_admin_test_keys(authorization: Optional[str] = Header(default=None)):
    _require_admin(authorization)
    s = server_manager.state.get("settings", {})
    diag = test_server_api_keys(
        primary_key=s.get("gemini_api_key", ""),
        fallback_key=s.get("gemini_fallback_api_key", ""),
    )
    return {"ok": True, "diagnostic": diag}
